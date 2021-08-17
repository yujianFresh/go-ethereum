package delegate_state

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
	"math/big"
)

type delegateObject struct {
	address  common.Address
	addrHash common.Hash // hash of eminer-pro address of the account
	data     Delegate
	db       *DelegateDB

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by DelegateDB.Commit.
	dbErr error

	// Write caches.
	trie          Trie    // storage trie, which becomes non-nil on first access
	cachedStorage Storage // Storage entry cache to avoid duplicate reads
	dirtyStorage  Storage // Storage entries that need to be flushed to disk

	touched  bool
	deleted  bool
	suicided bool
	onDirty  func(addr common.Address) // Callback method to mark a state object newly dirty
}

type Delegate struct {
	Root         common.Hash // merkle root of the storage trie
	Vote         *big.Int    // vote number
	Nickname     string      // delegate name
	RegisterTime uint64      // delegate register time
	Delete       bool        // whether delete
}

// Returns the address of the contract/account
func (d *delegateObject) Address() common.Address {
	return d.address
}

// newObject creates a state object.
func newObject(db *DelegateDB, address common.Address, delegate Delegate) *delegateObject {
	if delegate.Vote == nil {
		delegate.Vote = big.NewInt(0)
	}
	dObject := &delegateObject{
		db:            db,
		address:       address,
		addrHash:      crypto.Keccak256Hash(address[:]),
		data:          delegate,
		cachedStorage: make(Storage),
		dirtyStorage:  make(Storage),
	}
	dObject.tryMarkDirty()
	return dObject
}

func (d *delegateObject) getTrie(db Database) Trie {
	if d.trie == nil {
		var err error
		d.trie, err = db.OpenStorageTrie(d.addrHash, d.data.Root)
		if err != nil {
			d.trie, _ = db.OpenStorageTrie(d.addrHash, common.Hash{})
			d.setError(fmt.Errorf("can't create storage trie: %v", err))
		}
	}
	return d.trie
}

func (d *delegateObject) touch() {
	d.db.journal = append(d.db.journal, touchChange{
		account:   &d.address,
		prev:      d.touched,
		prevDirty: d.onDirty == nil,
	})
	if d.onDirty != nil {
		d.onDirty(d.Address())
		d.onDirty = nil
	}
	d.touched = true
}

func (d *delegateObject) Vote() *big.Int {
	return new(big.Int).Set(d.data.Vote)
}

func (d *delegateObject) SubVote(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	result := new(big.Int).Sub(d.Vote(), amount)
	if result.Cmp(common.Big0) < 0 {
		d.setVote(common.Big0)
	} else {
		d.setVote(result)
	}

}

func (d *delegateObject) AddVote(amount *big.Int) {
	if amount.Sign() == 0 {
		if d.empty() {
			d.touch()
		}

		return
	}
	d.setVote(new(big.Int).Add(d.Vote(), amount))
}

func (d *delegateObject) SetVote(amount *big.Int) {
	d.db.journal = append(d.db.journal, voteChange{
		account: &d.address,
		prev:    new(big.Int).Set(d.data.Vote),
	})
	d.setVote(amount)
}

func (d *delegateObject) setVote(amount *big.Int) {
	d.data.Vote = amount
	if d.onDirty != nil {
		d.onDirty(d.Address())
		d.onDirty = nil
	}
}

// GetState returns a value in account storage.
func (d *delegateObject) GetState(db Database, key common.Hash) common.Hash {
	value, exists := d.cachedStorage[key]
	if exists {
		return value
	}
	// Load from DB in case it is missing.
	enc, err := d.getTrie(db).TryGet(key[:])
	if err != nil {
		d.setError(err)
		return common.Hash{}
	}
	if len(enc) > 0 {
		_, content, _, err := rlp.Split(enc)
		if err != nil {
			d.setError(err)
		}
		value.SetBytes(content)
	}
	if (value != common.Hash{}) {
		d.cachedStorage[key] = value
	}
	return value
}

// SetState updates a value in account storage.
func (d *delegateObject) SetState(db Database, key, value common.Hash) {
	d.db.journal = append(d.db.journal, storageChange{
		account:  &d.address,
		key:      key,
		prevalue: d.GetState(db, key),
	})
	d.setState(key, value)
}

func (d *delegateObject) setState(key, value common.Hash) {
	d.cachedStorage[key] = value
	d.dirtyStorage[key] = value

	if d.onDirty != nil {
		d.onDirty(d.Address())
		d.onDirty = nil
	}
}

// updateTrie writes cached storage modifications into the object's storage trie.
func (d *delegateObject) updateTrie(db Database) Trie {
	tr := d.getTrie(db)
	for key, value := range d.dirtyStorage {
		delete(d.dirtyStorage, key)
		if (value == common.Hash{}) {
			d.setError(tr.TryDelete(key[:]))
			continue
		}
		// Encoding []byte cannot fail, ok to ignore the error.
		v, _ := rlp.EncodeToBytes(bytes.TrimLeft(value[:], "\x00"))
		d.setError(tr.TryUpdate(key[:], v))
	}
	return tr
}

// UpdateRoot sets the trie root to the current root hash of
func (d *delegateObject) updateRoot(db Database) {
	d.updateTrie(db)
	d.data.Root = d.trie.Hash()
}

// CommitTrie the storage trie of the object to dwb.
// This updates the trie root.
func (d *delegateObject) CommitTrie(db Database) error {
	if d.updateTrie(db) == nil {
		return nil
	}
	if d.dbErr != nil {
		return d.dbErr
	}
	root, err := d.trie.Commit(nil)
	if err == nil {
		d.data.Root = root
	}
	return err
}

func (d *delegateObject) markSuicided() {
	d.suicided = true
	d.tryMarkDirty()
}

func (d *delegateObject) deepCopy(db *DelegateDB) *delegateObject {
	stateObject := newObject(db, d.address, d.data)
	if d.trie != nil {
		stateObject.trie = db.db.CopyTrie(d.trie)
	}

	stateObject.dirtyStorage = d.dirtyStorage.Copy()
	stateObject.cachedStorage = d.dirtyStorage.Copy()
	stateObject.deleted = d.deleted
	return stateObject
}

func (d *delegateObject) empty() bool {
	return false
}

// setError remembers the first non-nil error it is called with.
func (d *delegateObject) setError(err error) {
	if d.dbErr == nil {
		d.dbErr = err
	}
}

// EncodeRLP implements rlp.Encoder.
func (d *delegateObject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, d.data)
}

func (d *delegateObject) tryMarkDirty() {
	if d.onDirty != nil {
		d.onDirty(d.Address())
		d.onDirty = nil
	}
}
