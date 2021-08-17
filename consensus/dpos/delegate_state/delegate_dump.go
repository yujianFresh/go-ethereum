package delegate_state

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

type DumpDelegate struct {
	Vote         uint64            `json:"vote"`
	Root         string            `json:"root"`
	Nickname     string            `json:"nickname"`
	RegisterTime uint64            `json:"registerTime"`
	Storage      map[string]string `json:"storage"`
}

type Dump struct {
	Root      string                  `json:"root"`
	Delegates map[string]DumpDelegate `json:"delegates"`
}

func (d *DelegateDB) RawDump() Dump {
	dump := Dump{
		Root:      fmt.Sprintf("%x", d.trie.Hash()),
		Delegates: make(map[string]DumpDelegate),
	}

	it := trie.NewIterator(d.trie.NodeIterator(nil))
	for it.Next() {
		addr := d.trie.GetKey(it.Key)
		var data Delegate
		if err := rlp.DecodeBytes(it.Value, &data); err != nil {
			panic(err)
		}

		obj := newObject(nil, common.BytesToAddress(addr), data)
		delegate := DumpDelegate{
			Vote:         data.Vote.Uint64(),
			Root:         common.Bytes2Hex(data.Root[:]),
			Storage:      make(map[string]string),
			Nickname:     data.Nickname,
			RegisterTime: data.RegisterTime,
		}
		storageIt := trie.NewIterator(obj.getTrie(d.db).NodeIterator(nil))
		for storageIt.Next() {
			delegate.Storage[common.Bytes2Hex(d.trie.GetKey(storageIt.Key))] = common.Bytes2Hex(storageIt.Value)
		}
		dump.Delegates[common.Bytes2Hex(addr)] = delegate
	}
	return dump
}

func (d *DelegateDB) Dump() []byte {
	jsonBytes, err := json.MarshalIndent(d.RawDump(), "", "    ")
	if err != nil {
		fmt.Println("dump err", err)
	}
	return jsonBytes
}
