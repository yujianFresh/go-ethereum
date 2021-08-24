package themis

import (
	"errors"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
	"sync"
)

const (
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory
)

// themis dpos protocol constants.
var (
	extraVanity           = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal             = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal
	diffInTurn            = big.NewInt(2)          // Block difficulty for in-turn signatures
	diffNoTurn            = big.NewInt(1)          // Block difficulty for out-of-turn signatures
	defaultEpochLength    = uint64(101)            // Default number of blocks after which vote's period of validity, About one week if period is 3
	defaultBlockPeriod    = uint64(10)             // Default minimum difference between two consecutive block's timestamps
	defaultMaxSignerCount = uint64(101)            //
	defaultBlockReward    = new(big.Int).Mul(big.NewInt(10), big.NewInt(1e+18))
	minVoterBalance       = new(big.Int).Mul(big.NewInt(100), big.NewInt(1e+18))
	uncleHash             = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// Themis is the dpos consensus engine
type Themis struct {
	chainConfig *params.ChainConfig  // Chain config
	config      *params.ThemisConfig // Consensus engine configuration parameters for themis consensus
	db          ethdb.Database       // Database to store and retrieve snapshot checkpoints

	recentSnaps *lru.ARCCache // Snapshots for recent block to speed up
	signatures  *lru.ARCCache // Signatures of recent blocks to speed up mining

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with

	lock sync.RWMutex // Protects the signer fields

	ethAPI *ethapi.PublicBlockChainAPI
	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

// New creates a Themis consensus engine.
func New(
	chainConfig *params.ChainConfig,
	db ethdb.Database,
	ethAPI *ethapi.PublicBlockChainAPI,
) *Themis {
	// Set any missing consensus parameters to their defaults
	conf := *chainConfig.Themis
	if conf.Epoch == 0 {
		conf.Epoch = defaultEpochLength
	}
	if conf.Period == 0 {
		conf.Period = defaultBlockPeriod
	}
	if conf.MaxSignerCount == 0 {
		conf.MaxSignerCount = defaultMaxSignerCount
	}
	if conf.MinVoterBalance.Uint64() > 0 {
		minVoterBalance = conf.MinVoterBalance
	}
	if conf.BlockReward == nil {
		conf.BlockReward = defaultBlockReward
	}

	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)

	return &Themis{
		chainConfig: chainConfig,
		config:      chainConfig.Themis,
		db:          db,
		ethAPI:      ethAPI,
		recentSnaps: recents,
		signatures:  signatures,
	}
}

// change block reward by replace this method
func accumulateRewards2(config *params.ThemisConfig, state *state.StateDB, header *types.Header) error {
	blockReward := config.BlockReward
	// Accumulate the rewards for the miner and any included uncles
	reward := new(big.Int).Set(blockReward)
	state.AddBalance(header.Coinbase, reward)
	return nil
}

func (t *Themis) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, t.signatures)
}

func (t *Themis) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return t.verifyHeader(chain, header, nil)
}

func (t *Themis) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Short circuit if the header is known, or its parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	if header.Time <= parent.Time {
		return errors.New("timestamp older than parent")
	}
	// TODO verify validator signatures

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}
	// TODO verify snapshot
	return nil
}

func (t *Themis) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := t.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (t *Themis) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

func (t *Themis) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// TODO
	return nil
}

func (t *Themis) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// TODO
	return nil
}

func (t *Themis) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	// TODO
}

func (t *Themis) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// TODO
	return nil, nil
}

func (t *Themis) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	// TODO
	return nil
}

func encodeSigHeader(w io.Writer, header *types.Header) {
	err := rlp.Encode(w, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

func (t *Themis) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

func (t *Themis) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	snap, err := t.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return CalcDifficulty(snap, t.signer)
}

func (t *Themis) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// TODO
	return nil, nil
}

func CalcDifficulty(snap *Snapshot, signer common.Address) *big.Int {
	if snap.inturn(snap.Number+1, signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

func (t *Themis) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "themis",
		Version:   "1.0",
		Service:   &API{chain: chain, themis: t},
		Public:    false,
	}}
}

func (t *Themis) Close() error {
	return nil
}
