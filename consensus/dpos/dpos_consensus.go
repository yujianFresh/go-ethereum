package dpos

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/dpos/delegate_state"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"math"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	allowedFutureBlockTime = 15 * time.Second // Max time from current time allowed for blocks, before they're considered future blocks
	errZeroBlockTime       = errors.New("timestamp equals parent's")
)

// Config are the configuration parameters of the ethash.
type Config struct {
	CacheDir string
}

type DacchainDpos struct {
	// config Config
	lock sync.Mutex
}

func New() *DacchainDpos {
	return &DacchainDpos{}
}

// annul with 15% profit,AccumulateRewards credits the coinbase of the given block with the produce reward
func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header) {
	// begin with 100 reward
	var (
		// begin with 100 reward
		basicReward        float64 = 100
		annulProfit                = params.AnnulProfit
		annulBlockAmount           = params.AnnulBlockAmount
		blockReward                = big.NewInt(1e+18)
	)
	yearNumber := header.Number.Int64() / annulBlockAmount.Int64()
	currentReward := (int64)(basicReward * math.Pow(annulProfit, float64(yearNumber)))
	precisionReward := new(big.Int).Mul(big.NewInt(currentReward), blockReward)
	reward := new(big.Int).Set(precisionReward)
	state.AddBalance(header.Coinbase, reward)
}

// check parent exist and cache header
func (d *DacchainDpos) Prepare(chain consensus.ChainReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return nil
}

func (d *DacchainDpos) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, dState *delegate_state.DelegateDB, txs []*types.Transaction, receipts []*types.Receipt) (*types.Block, error) {
	accumulateRewards(chain.Config(), state, header)

	header.Root = state.IntermediateRoot(false)
	header.DelegateRoot = dState.IntermediateRoot(false)

	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs,nil, receipts), nil

}

func (d *DacchainDpos) VerifyHeaderAndSign(chain consensus.ChainReader, block *types.Block, currentShuffleList *types.ShuffleList, blockInterval int) error {
	header := block.Header()
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	blockTime := header.Time
	currentTime := time.Now().Unix()
	if currentTime < int64(blockTime) || (currentTime >= (int64(blockTime) + int64(blockInterval))) {
		errMsg := fmt.Sprintf("block time is expire|blockNumber:%d blockTime:%d currentTime:%d", block.NumberU64(), blockTime, currentTime)
		return errors.New(errMsg)
	}
	if parent == nil {
		errMsg := fmt.Sprintf("unknown ancestor|currentBlockNumber:%d blockParentHash:%s", block.NumberU64(), block.ParentHash().Hex())
		return errors.New(errMsg)
	}
	err := d.verifyHeader(chain, header, parent)
	if err != nil {
		return err
	}
	coinbase := header.Coinbase.Hex()
	coinbaseSign := block.Signature
	if len(coinbaseSign) == 0 {
		errMsg := fmt.Sprintf("miss Signature blockNumber:%d", block.NumberU64())
		return errors.New(errMsg)
	}
	var delegate types.ShuffleDel
	var exist bool
	log.Debug("VerifyHeaderAndSign", "coinbase", coinbase, "shuffleDelsLen", len(currentShuffleList.ShuffleDels))
	for _, v := range currentShuffleList.ShuffleDels {
		if strings.EqualFold(v.Address, coinbase) {
			delegate = v
			exist = true
			break
		}
	}
	if !exist {
		return errors.New(fmt.Sprintf("coinbase:%s not exist in current shuffle list", coinbase))
	}
	log.Debug("VerifyHeaderAndSign", "delegate", delegate)
	if blockTime != delegate.WorkTime {
		errMsg := fmt.Sprintf("timeStamp not same blockNumber:%d coinbase:%s blockTime:%d shuffleTime:%d", block.NumberU64(), coinbase, blockTime, delegate.WorkTime)
		return errors.New(errMsg)
	}
	pubkey, err := secp256k1.RecoverPubkey(block.Hash().Bytes()[:32], coinbaseSign)
	log.Debug("VerifyHeaderAndSign", "coinbaseSign", coinbaseSign, "blockHash", block.Hash().Bytes(), "pubkey", pubkey, "err", err)
	//if err != nil {
	//	return err
	//}
	unmarshalPubkey, _ := crypto.UnmarshalPubkey(pubkey)
	pubAddress := crypto.PubkeyToAddress(*unmarshalPubkey).Hex()
	if !strings.EqualFold(pubAddress, coinbase) {
		errMsg := fmt.Sprintf("sign address error blockNumber:%d coinbase:%s signAddress:%s", block.NumberU64(), coinbase, pubAddress)
		return errors.New(errMsg)
	}
	return nil
}

func (d *DacchainDpos) VerifySignatureSend(blockHash common.Hash, confirmSign []byte, currentShuffleList *types.ShuffleList) error {
	confirmPubkey, err := secp256k1.RecoverPubkey(blockHash.Bytes()[:32], confirmSign)
	unmarshalPubkey, _ := crypto.UnmarshalPubkey(confirmPubkey)
	if err != nil {
		return err
	}
	confirmPubAddress := crypto.PubkeyToAddress(*unmarshalPubkey).Hex()
	for _, v := range currentShuffleList.ShuffleDels {
		if strings.EqualFold(v.Address, confirmPubAddress) {
			return nil
		}
	}
	errMsg := fmt.Sprintf("%s isn't in currentShuffleList blockHash:%s", confirmPubAddress, blockHash.Hex())
	return errors.New(errMsg)
}

func (d *DacchainDpos) VerifyBlockGenerate(chain consensus.ChainReader, block *types.Block, currentShuffleList *types.ShuffleList, blockInterval int) error {
	genesisConfig := chain.Config()
	maxElectDelegate := genesisConfig.MaxElectDelegate.Int64()
	delegateAmount := (maxElectDelegate / 3) * 2
	err := d.VerifyHeaderAndSign(chain, block, currentShuffleList, blockInterval)
	if err != nil {
		return err
	}
	// rlp decode
	rlpEncodeSigns := block.RlpEncodeSigns
	var signs []types.VoteSign
	err = rlp.DecodeBytes(rlpEncodeSigns, &signs)
	if err != nil {
		return err
	}

	checkSignAddressMap := make(map[string]byte, 0)
	blockHashBytes := block.Hash().Bytes()
	for _, sign := range signs {
		tempPubKey, _ := secp256k1.RecoverPubkey(blockHashBytes[:32], sign.Sign)
		unmarshalPubkey, _ := crypto.UnmarshalPubkey(tempPubKey)
		tempPubAddress := crypto.PubkeyToAddress(*unmarshalPubkey).Hex()
		if checkInShuffleList(currentShuffleList, tempPubAddress) {
			checkSignAddressMap[tempPubAddress] = 1
		}
	}
	if len(checkSignAddressMap) > int(delegateAmount) {
		return nil
	}
	errMsg := fmt.Sprintf("delegate sign not enough blockNumber:%d need check signs:%d actual check signs:%d", block.NumberU64(), delegateAmount, len(checkSignAddressMap))
	return errors.New(errMsg)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (d *DacchainDpos) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header) (chan<- struct{}, <-chan error) {

	// // If we're running a full engine faking, accept any input as valid
	if len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		return abort, results
	}

	// Spawn as many workers as allowed threads
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}

	// Create a task channel and spawn the verifiers
	var (
		inputs       = make(chan int)
		done         = make(chan int, workers)
		headerErrors = make([]error, len(headers))
		abort        = make(chan struct{})
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				headerErrors[index] = d.verifyHeaders(chain, headers, index)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- headerErrors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (d *DacchainDpos) verifyHeaders(chain consensus.ChainReader, headers []*types.Header, index int) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}

	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if chain.GetHeader(headers[index].Hash(), headers[index].Number.Uint64()) != nil {
		return nil // known block
	}

	return d.verifyHeader(chain, headers[index], parent)
}

// verifyHeader checks whether a header conforms to the consensus rules of the DAC engine
func (d *DacchainDpos) verifyHeader(chain consensus.ChainReader, header, parent *types.Header) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	if header.Time > uint64(time.Now().Add(allowedFutureBlockTime).Unix()) {
		return consensus.ErrFutureBlock
	}

	if header.Time <= parent.Time {
		return errZeroBlockTime
	}

	maxGasLimit := uint64(0x7fffffffffffffff)
	if header.GasLimit > maxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, maxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / params.GasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < params.MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}

	return nil
}

func (d *DacchainDpos) VerifyHeader(chain consensus.ChainReader, header *types.Header) error {
	// Short circuit if the header is known, or it's parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	if time.Now().Unix() < int64(header.Time) {
		return consensus.ErrFutureBlock
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return d.verifyHeader(chain, header, parent)
}

// APIs implements consensus.Engine, returning the user facing RPC APIs. Currently
// that is empty.
func (d *DacchainDpos) APIs(chain consensus.ChainReader) []rpc.API {
	return nil
}

func (d *DacchainDpos) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func checkInShuffleList(currentShuffleList *types.ShuffleList, address string) bool {
	for _, v := range currentShuffleList.ShuffleDels {
		if strings.EqualFold(v.Address, address) {
			return true
		}
	}
	return false
}
