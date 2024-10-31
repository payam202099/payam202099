// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20FlashMint.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Wrapper.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Counters.sol"; 
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC777/ERC777.sol";
interface ICrossChainBridge {
  function deposit(uint256 _amount, address _recipient) external;
  function withdraw(uint256 _amount, address _recipient) external;
  function getChainId() external view returns (uint256);
}

interface IETH {
  function transfer(address recipient, uint256 amount) external returns (bool);
}

interface IStablecoin {
function mint(address to, uint256 amount) external;
function burn(uint256 amount) external;
function balanceOf(address account) external view returns (uint256);
function transfer(address to, uint256 amount) external;
}
contract NetworkFeeManager {
using Counters for Counters.Counter;
Counters.Counter private transactionFeeReductionCount;

struct FeeReductionRecord {
 uint256 timestamp;
 uint256 gasPrice;
 uint256 gasLimit;
}

mapping(uint256 => FeeReductionRecord) public transactionFeeReductionHistory;

struct ReduceFeeParams {
 uint256 gasPrice;
 uint256 gasLimit;
 uint256 maxGasPriceReduction; // Percentage
 uint256 maxGasLimitReduction; // Percentage
 uint256 minGasPrice;
 uint256 minGasLimit;
 uint256 gasPriceStep;
 uint256 gasLimitStep;
 uint256 maxIterations;
 bool useDynamicSteps;
}

event NetworkFeeReduced(
 uint256 oldGasPrice,
 uint256 newGasPrice,
 uint256 oldGasLimit,
 uint256 newGasLimit
);

function reduceNetworkFeeAdvanced(ReduceFeeParams memory params) public returns (uint256 newGasPrice, uint256 newGasLimit) {

 require(
params.gasPrice > params.minGasPrice,
"Initial gas price is already below minimum"
 );
 require(
params.gasLimit > params.minGasLimit,
"Initial gas limit is already below minimum"
 );

 uint256 maxGasPriceReductionWei = (params.gasPrice * params.maxGasPriceReduction) / 100;
 uint256 maxGasLimitReductionWei = (params.gasLimit * params.maxGasLimitReduction) / 100;

 newGasPrice = params.gasPrice - maxGasPriceReductionWei;
 if (newGasPrice < params.minGasPrice) {
newGasPrice = params.minGasPrice;
 }

 newGasLimit = params.gasLimit - maxGasLimitReductionWei;
 if (newGasLimit < params.minGasLimit) {
newGasLimit = params.minGasLimit;
 }

 uint256 iterations = 0;
 while (
newGasPrice > params.minGasPrice &&
newGasLimit > params.minGasLimit &&
iterations < params.maxIterations
 ) {
if (params.useDynamicSteps) {
  uint256 previousReductionCount = transactionFeeReductionCount.current() - 1;
  if (previousReductionCount > 0) {
 uint256 previousGasPrice = transactionFeeReductionHistory[previousReductionCount].gasPrice;
 uint256 previousGasLimit = transactionFeeReductionHistory[previousReductionCount].gasLimit;

 params.gasPriceStep = Math.min(
params.gasPriceStep,(previousGasPrice - newGasPrice) / 2
 );
 params.gasLimitStep = Math.min(
params.gasLimitStep,
(previousGasLimit - newGasLimit) / 2
 );
  }
}

newGasPrice = (newGasPrice > params.gasPriceStep)
  ? newGasPrice - params.gasPriceStep
  : params.minGasPrice;

newGasLimit = (newGasLimit > params.gasLimitStep)
  ? newGasLimit - params.gasLimitStep
  : params.minGasLimit;

iterations++;
 }

 transactionFeeReductionCount.increment();transactionFeeReductionHistory[transactionFeeReductionCount.current()] = FeeReductionRecord(block.timestamp, newGasPrice, newGasLimit);

 emit NetworkFeeReduced(
params.gasPrice,
newGasPrice,
params.gasLimit,
newGasLimit
 );
}
}
contract MicroGoldCoin is ReentrancyGuard,Ownable {  
 using SafeMath for uint256;
 address public _owner;
 using ECDSA for bytes32;
 using Counters for Counters.Counter;
 enum TransactionStatus { Unverified, Recorded }

Counters.Counter private _transactionIds;
Counters.Counter private transactionIdCounter;
uint256 public nance;
string public name;
string public symbol;
uint8 public decimals;
uint256 public totalSupply;
IERC20 public token; // تعریف متغیر token
uint256 public gasPrice;
uint256 transactionFee = 2;

uint256 public constant BURN_RATE = 5;
bool public paused;
bool private locked;
struct Transaction {
address from;
address to;
bytes signature;
TransactionStatus status;
uint256 amount;
uint256 timestamp;
bytes32 hash; 
bool isSuspicious; 
string reason; 
uint256 id; 
bool flagged;  
address signer; // اضافه کردن فیلد signer
}
  struct UserActivity {
uint256 recentTransactionCount; // Number of recent transactions
uint256[] recentTransactions; // Array of recent transaction IDs
uint256 lastTransactionTimestamp; // Timestamp of the last transaction
bool blacklisted; // Flag to indicate if the user is blacklisted
string blacklistReason; 
uint256[] flaggedTransactions; // لیستی از ID تراکنش‌های علامت‌گذاری شده
  }
  
uint256 public maxTransactionAmount;
uint256 public minTransactionAmount;

  uint256 public recentTransactionThreshold = 5;
  uint256 public recentTransactionTimeframe = 10 minutes;
  uint256 public maxTransactionFrequency = 10; // Maximum number of transactions per minute
  uint256 public blacklistingThreshold = 100; // Number of flagged transactions required for blacklisting

uint256 public blacklistDuration = 30 days; // Duration of blacklisting in seconds

// Event for flagged transactions
mapping(address => uint256) public balances; // نگه‌داشتن موجودی هر کاربر
  
mapping(address => uint256) public balanceOf;
mapping(address => mapping(address => uint256)) public allowance;
mapping(address => bool) public frozenAccount;
mapping(address => uint256) public numTransactionsFrom;
mapping (address => uint256) public numTransactionsTo;
mapping (bytes32 => bool) public suspiciousTransactions;
mapping (bytes32 => uint256) public batchTransactions;
// Additional functions
mapping(address => uint256) public lastTransferTimestamp;
uint256 public dailyTransferLimit;
mapping(uint256 => Transaction) public transactions; // نگهداری تراکنش‌ها
mapping(address => UserActivity) public transactionHistory; // نگهداری تاریخچه کاربر
mapping(address => bool) public pausedFor;
mapping(address => uint256) public nonces;
mapping(address => uint256) public transactionFees;

event TransactionFlagged(uint256 transactionId, address from, address to, uint256 amount, string reason);

// Event for blacklisted users
event UserBlacklisted(address user, string reason);

// Event for unblacklisted users
event UserUnblacklisted(address user);
event AccountUnfrozen(address account);
event AccountWhitelisted(address account);
event AccountRemovedFromWhitelist(address account);
event TransactionInitialized(uint256 transactionId, address from, address to, uint256 amount);
event TransactionExecuted(uint256 transactionId, address executor);
event TransactionAccelerated(address indexed recipient, uint256 amount, uint256 transactionFee);
event ProposalCreated(uint256 indexed proposalId, string title, string description);
event ProposalClosed(uint256 indexed proposalId, bool passed);
event ProposalExecuted(uint256 indexed proposalId);
event ProposalDefeated(uint256 indexed proposalId);
 event vote(uint256 offerId, bool inFavor);
bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
event DailyTransferLimitReached(address indexed sender, uint256 timestamp);
event Transfer(address indexed from, address indexed to, uint256 value);
event BalanceUpdated(address indexed user, uint256 newBalance);
event FrozenFunds(address target, bool frozen);
event Approval(address indexed _owner, address indexed spender, uint256 value);
event Burn(address indexed from, uint256 value);
event GasPriceChanged(uint256 newGasPrice);
event Paused(address account);
event Unpaused(address account);
event SignatureSet(uint256 indexed transactionId, address indexed signer, bytes signature);
event TransactionStatusUpdated(uint256 indexed transactionId, TransactionStatus status);



modifier onlyUnpaused() {
 require(!paused, "Contract is paused");
 _;
}
modifier gasLimit(uint256 _gasLimit) {
 require(gasleft() >= _gasLimit, "Insufficient gas");
 _;
}

modifier notFrozen(address _address) {
 require(!frozenAccount[_address], "Account is frozen");
 _;
}
modifier whenNotPaused() {
require(!paused, "Contract is paused");
_;
}
modifier whenPaused() {
require(paused, "Contract is not paused");
_;
}
modifier noReentrancy() {
require(!locked, "No reentrancy");
locked = true;
_;
locked = false;
}
    constructor() Ownable(msg.sender) {
 name = "MicroGold";
 symbol = "MGAC";
 decimals = 7;
 totalSupply = 50000000;
 balanceOf[msg.sender] = totalSupply;
 gasPrice = tx.gasprice;
 _owner = msg.sender;
 paused = false;
 _owner = msg.sender;
maxTransactionAmount = 1000;
minTransactionAmount = 1 ;
 balanceOf[msg.sender] = totalSupply;
 gasPrice = 100;  // Initial gas price
 dailyTransferLimit = 10000;  // Initial daily transfer limit
 emit Transfer(address(0), msg.sender, totalSupply);
}
function setOwner(address newOwner) public onlyOwner {
    _owner = newOwner;  // اینجا به روزرسانی درست است
}
// Approve function
function approve(address _spender, uint256 _value) public returns (bool) {
 allowance[msg.sender][_spender] = _value;
 emit Approval(msg.sender, _spender, _value);
 return true;
}
function burn(uint256 _value) public {
 require(balanceOf[msg.sender] >= _value, "Insufficient balance");

 balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
 totalSupply = totalSupply.sub(_value);
 
 emit Burn(msg.sender, _value);
}

function freezeAccount(address _address) public onlyOwner {
 frozenAccount[_address] = true;
 emit FrozenFunds(_address, true);
}
function unfreezeAccount(address _address) public onlyOwner {
 frozenAccount[_address] = false;
 emit FrozenFunds(_address, false);
}

function pause() public onlyOwner {
 paused = true;
 emit Paused(msg.sender);
}

function unpause() public onlyOwner {
 paused = false;
 emit Unpaused(msg.sender);
}

function getPaused() public view returns (bool) {
 return paused;
}

// Set gas price function
function setGasPrice(uint256 _gasPrice) public onlyOwner {
 gasPrice = _gasPrice;
 emit GasPriceChanged(_gasPrice);
}

// New functions
function setDailyTransferLimit(uint256 _dailyTransferLimit) public onlyOwner {
 dailyTransferLimit = _dailyTransferLimit;
}

function getDailyTransferLimit() public view returns (uint256) {
 return dailyTransferLimit;
}
function transfer(address _to, uint256 _value) public returns (bool) {
require(!frozenAccount[msg.sender], "Sender account is frozen");
require(!frozenAccount[_to], "Recipient account is frozen");
require(!paused, "Contract is paused");

uint256 totalAmount = _value.add(transactionFee); // مجموع مقدار انتقال و کارمزد
  require(balanceOf[msg.sender] >= totalAmount, "Insufficient balance");

// بررسی محدودیت انتقال روزانه
if (block.timestamp - lastTransferTimestamp[msg.sender] < 24 * 60 * 60) {
revert("Transfer limit exceeded; please wait 24 hours before the next transfer");
}

// به‌روزرسانی موجودی‌ها
balanceOf[msg.sender] = balanceOf[msg.sender].sub(totalAmount); // کسر مقدار انتقال و کارمزد
balanceOf[_to] = balanceOf[_to].add(_value); // اضافه کردن مقدار منتقل‌شده به گیرنده

lastTransferTimestamp[msg.sender] = block.timestamp; // به‌روزرسانی زمان آخرین انتقال
emit Transfer(msg.sender, _to, _value); // ثبت رویداد انتقال

return true; // در صورت موفقیت
}
function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
require(!frozenAccount[msg.sender], "Sender account is frozen");
require(!frozenAccount[_from], "From account is frozen");
require(!frozenAccount[_to], "To account is frozen");
require(!paused, "Contract is paused");
require(balanceOf[_from] >= _value.add(transactionFee), "Insufficient balance"); // کارمزد 1 توکن
require(allowance[_from][msg.sender] >= _value, "Insufficient allowance");
require(balanceOf[_from] >= _value.add(transactionFee), "Insufficient balance to cover transactionFee and burn");

balanceOf[_from] = balanceOf[_from].sub(_value.add(transactionFee)); // کسر مقدار انتقال و کارمزد
balanceOf[_to] = balanceOf[_to].add(_value); // اضافه کردن مقدار منتقل‌شده به گیرنده
allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
return true;
}
function sendTokengo(address wallet, uint256 amount) public onlyOwner whenNotPaused {
 require(wallet != address(0), "Invalid wallet address");
 require(amount > 0, "Amount must be greater than 0");
 address from = msg.sender;
 address to = wallet;
 require(!frozenAccount[from], "Your account is frozen");
 require(amount <= balanceOf[from], "Insufficient balance");
 uint256 limit;
if (from == _owner || to == _owner) {
 // Your logic here
 
limit = balanceOf[from];
} else if (numTransactionsFrom[from] == 0) {
limit = balanceOf[from].mul(20).div(100); // 20% transaction limit for the first transaction
 } else {
limit = balanceOf[from].mul(5).div(100); // 5% transaction limit for subsequent transactions
 }

 require(amount <= limit, "Transfer amount exceeds the transaction limit");

 token.transferFrom(from, to, amount);

 _transfer(from, to, amount);

 emit Transfer(from, to, amount);
}
function _transfer(address from, address to, uint256 amount) internal {
 balanceOf[from] = balanceOf[from].sub(amount);
 balanceOf[to] = balanceOf[to].add(amount);

 numTransactionsFrom[from] = numTransactionsFrom[from].add(1);
 numTransactionsTo[to] = numTransactionsTo[to].add(1);
}
function setRecentTransactionThreshold(uint256 _recentTransactionThreshold) public onlyOwner {
 recentTransactionThreshold = _recentTransactionThreshold;
}
// Function to set the maximum transaction amount
function setMaxTransactionAmount(uint256 _maxTransactionAmount) public onlyOwner {
 maxTransactionAmount = _maxTransactionAmount;
}

// Function to set the minimum transaction amount
function setMinTransactionAmount(uint256 _minTransactionAmount) public onlyOwner {
 minTransactionAmount = _minTransactionAmount;
}
function flagTransaction(uint256 _transactionId, string memory _reason) private {
 Transaction storage transaction = transactions[_transactionId];
 if (!transaction.flagged) {
transaction.flagged = true;
transaction.reason = _reason;

// Check if the user should be blacklisted
if (transactionHistory[transaction.from].flaggedTransactions.length >= blacklistingThreshold) {
  blacklistUser(transaction.from, _reason);
}

// Emit event for flagged transactions
emit TransactionFlagged(_transactionId, transaction.from, transaction.to, transaction.amount, _reason);
 }
}

// Function to blacklist a user
function blacklistUser(address _user, string memory _reason) private {
 UserActivity storage userActivity = transactionHistory[_user];
 if (!userActivity.blacklisted) {
userActivity.blacklisted = true;
userActivity.blacklistReason = _reason;

// Emit event for blacklisted users
emit UserBlacklisted(_user, _reason);
 }
}

// Function to unblacklist a user
function unblacklistUser(address _user) public onlyOwner {
 UserActivity storage userActivity = transactionHistory[_user];
 if (userActivity.blacklisted) {
if (block.timestamp > userActivity.lastTransactionTimestamp + blacklistDuration) {
  userActivity.blacklisted = false;
  userActivity.blacklistReason = "";

  // Emit event for unblacklisted users
  emit UserUnblacklisted(_user);
} else {
  revert("User is still blacklisted");
}
 } else {
revert("User is not blacklisted");
 }
}

 
// Function to get the reason for blacklisting a user
function getBlacklistReason(address _user) public view returns (string memory) {
 return transactionHistory[_user].blacklistReason;
}

// Function to get the flagged transactions for a user
function getFlaggedTransactions(address _user) public view returns (uint256[] memory) {
 UserActivity memory userActivity = transactionHistory[_user];
 return userActivity.flaggedTransactions;
}


// Function to set the recent transaction timeframe
// تابعی برای تنظیم زمان اخیر تراکنش
function setRecentTransactionTimeframe(uint256 _recentTransactionTimeframe) public onlyOwner {
 recentTransactionTimeframe = _recentTransactionTimeframe;
}

// تابع برای بررسی فعالیت مشکوک
function checkSuspiciousActivity(uint256 _transactionId) private {
 Transaction storage transaction = transactions[_transactionId];

 // Check if the transaction is within the allowed frequency
 if (transactionHistory[transaction.from].lastTransactionTimestamp + recentTransactionTimeframe < block.timestamp) {
// Reset the counter if sufficient time has passed
transactionHistory[transaction.from].recentTransactionCount = 0;
 }

 // Update the transaction timestamp
 transactionHistory[transaction.from].lastTransactionTimestamp = block.timestamp;
 transactionHistory[transaction.from].recentTransactionCount++;

 if (transactionHistory[transaction.from].recentTransactionCount > maxTransactionFrequency) {
flagTransaction(_transactionId, "Too frequent transactions");
 }
}function shift(uint256[] storage arr) internal {
require(arr.length > 0, "Array is empty"); // بررسی اینکه آرایه خالی نیست
for (uint256 i = 1; i < arr.length; i++) {
 arr[i-1] = arr[i]; // جابجایی عناصر
}
arr.pop(); // حذف آخرین عنصر که حالا تکراری است
}

function setMaxTransactionFrequency(uint256 _maxTransactionFrequency) public onlyOwner {
 maxTransactionFrequency = _maxTransactionFrequency;
}

// Function to set the blacklisting threshold
function setBlacklistingThreshold(uint256 _blacklistingThreshold) public onlyOwner {
 blacklistingThreshold = _blacklistingThreshold;
}

// Function to set the blacklist duration
function setBlacklistDuration(uint256 _blacklistDuration) public onlyOwner {
 blacklistDuration = _blacklistDuration;
}

// Function to record a new transaction
function recordTransaction(address _from, address _to, uint256 _amount) public {
 // Check if the user is blacklisted
 if (transactionHistory[_from].blacklisted) {
revert("User is blacklisted");
 }

 // Check if the transaction amount is within the allowed range
 if (_amount > maxTransactionAmount || _amount < minTransactionAmount) {
revert("Transaction amount is outside the allowed range");
 }

 // Check if the transaction involves the zero address
 if (_from == address(0) || _to == address(0)) {
revert("Transaction cannot involve the zero address");
 }

 // Check if the transaction timestamp is valid (not in the future)
 if (block.timestamp > block.timestamp) {
revert("Invalid transaction timestamp");
 }

 uint256 newTransactionId = transactionIdCounter.current();
 transactionIdCounter.increment();

 updateTransactionHistory(_from, newTransactionId);

// Check for suspicious activity
 checkSuspiciousActivity(newTransactionId);
}

 function updateTransactionHistory(address _user, uint256 _transactionId) private {
 UserActivity storage userActivity = transactionHistory[_user];
 userActivity.recentTransactions.push(_transactionId);

 // بررسی تعداد تراکنش‌ها و حذف اولین عنصر در صورت لزوم
 if (userActivity.recentTransactions.length > recentTransactionThreshold) {
// استفاده از برش (Slice) برای حفظ فقط عناصری که می‌خواهیم
uint256[] memory newRecentTransactions = new uint256[](recentTransactionThreshold);
for (uint256 i = 1; i < userActivity.recentTransactions.length; i++) {
  newRecentTransactions[i - 1] = userActivity.recentTransactions[i]; // پر کردن آرایه جدید
}
userActivity.recentTransactions = newRecentTransactions; 
 }
 userActivity.recentTransactionCount = userActivity.recentTransactions.length;
 userActivity.lastTransactionTimestamp = block.timestamp;
}

 function addSuspiciousTransaction(bytes32 transactionHash, uint amount, address from, address to) internal {
// Check if transaction exceeds transfer limit or number of transactions from/to exceeds threshold
if (amount > 10000 || numTransactionsFrom[from] > 20 || numTransactionsTo[to] > 20) {
 suspiciousTransactions[transactionHash] = true;
}
}

function checkSuspiciousTransaction(bytes32 transactionHash) public view returns (bool) {
return suspiciousTransactions[transactionHash];
}
function emergencyWithdraw(address _tokenAddress, uint256 _amount) public onlyOwner {
 token = IERC20(_tokenAddress);
token.transfer(msg.sender, _amount);
} 
function withdrawTransactionFees() public onlyOwner {
address payable _ownerAddress = payable(address(_owner)); // تعریف مالک به صورت آدرس قابل انتقال
uint256 balance = address(this).balance; // دریافت موجودی contract

// ارسال موجودی به مالک contract
(bool success, ) = _ownerAddress.call{value: balance}("");
require(success, "Transfer failed");
}
function setTransactionSignature(uint256 transactionId, bytes memory signature) public {
require(transactions[transactionId].status == TransactionStatus.Unverified, "Transaction already recorded");

transactions[transactionId] = Transaction({
from: transactions[transactionId].from,// آدرس فرستنده
to: transactions[transactionId].to,  // آدرس گیرنده
signature: signature,  // امضا
status: TransactionStatus.Recorded,  // وضعیت
amount: transactions[transactionId].amount,// مقدار
timestamp: block.timestamp, // زمان فعلی
hash: keccak256(abi.encodePacked(transactionId, signature)), // تولید هش
isSuspicious: false,
reason: "",
id: transactionId,
flagged: false,  
signer: msg.sender
});

emit SignatureSet(transactionId, msg.sender, signature);
}

function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
}

function verifySignature(uint256 transactionId) public view returns (address) {
Transaction memory txn = transactions[transactionId];
bytes32 messageHash = toEthSignedMessageHash(txn.hash);
(address signer) = recoverSigner(messageHash, txn.signature);
return signer;
}
function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
(uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
return ecrecover(messageHash, v, r, s);
}function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
require(sig.length == 65, "Invalid signature length");
assembly {r := mload(add(sig, 32))s := mload(add(sig, 64)) v := byte(0, mload(add(sig, 96)))v := add(v, 27)}}
function getTransactionSignature(uint256 transactionId) public view returns (bytes memory){return transactions[transactionId].signature;}}

    

contract AdvancedToken is Ownable, Pausable {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    uint256 public initialSupply;
    string public name = "MyToken"; // نام توکن
    string public symbol = "MTK"; // نماد توکن
    uint8 public decimals = 18; // تعداد اعشار
    uint256 public totalSupply; // کل موجودی توکن

    // Constants for reward thresholds
    uint256 private constant REWARD_THRESHOLD_1 = 100;
    uint256 private constant REWARD_THRESHOLD_2 = 10000;
    uint256 private constant REWARD_THRESHOLD_3 = 100000;
    uint256 private constant REWARD_THRESHOLD_4 = 1000000;
    uint256 private constant REWARD_THRESHOLD_5 = 100000000;

    // Initial reward amounts
    uint256 public rewardAmount1 = 5 * (10 ** 18); // 5 tokens
    uint256 public rewardAmount2 = 500 * (10 ** 18); // 500 tokens
    uint256 public ethRewardAmount = 0.5 ether; // 0.5 ETH
    uint256 public etherRewardAmount = 30 ether;
    
    address public ethContractAddress;
    uint256 public dailyTransferLimit;

    // Mapping for token balances
    mapping(address => uint256) public balanceOf;

    // Mapping for transaction counts
    mapping(address => uint256) public transactionCount;

    // Mapping for allowances
    mapping(address => mapping(address => uint256)) public allowance;

    // Mapping for frozen accounts
    mapping(address => bool) public frozenAccount;

    // Event for transfers
    event Transfer(address indexed from, address indexed to, uint256 value);

    // Event for ETH rewards
    event EthReward(address indexed user, uint256 amount);

    // Event for account freezing
    event AccountFrozen(address account);

    // Event for account unfreezing
    event AccountUnfrozen(address account);
    
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) Ownable(msg.sender) {
        totalSupply = _initialSupply * (10 ** uint256(decimals)); // مقداردهی اولیه
        balanceOf[msg.sender] = totalSupply; // تخصیص تمام توکن‌ها به سازنده
    }



    // Function to freeze an account
    function freezeAccount(address _account) external onlyOwner {
        frozenAccount[_account] = true;
        emit AccountFrozen(_account);
    }

    // Function to unfreeze an account
    function unfreezeAccount(address _account) external onlyOwner {
        frozenAccount[_account] = false;
        emit AccountUnfrozen(_account);
    }

    // Function to increase the balance of an account
    function increaseBalance(address _account, uint256 _amount) external onlyOwner {
        balanceOf[_account] = balanceOf[_account].add(_amount);
    }

    // Function to decrease the balance of an account
    function decreaseBalance(address _account, uint256 _amount) external onlyOwner {
        require(balanceOf[_account] >= _amount, "Insufficient balance");
        balanceOf[_account] = balanceOf[_account].sub(_amount);
    }

    // Function to set the ETH reward amount
    function setEthRewardAmount(uint256 _amount) external onlyOwner {
        ethRewardAmount = _amount;
    }

    function approve(address _spender, uint256 _amount) public returns (bool) {
        require(_spender != address(0), "Invalid spender address");
        allowance[msg.sender][_spender] = _amount; // تنظیم تأییدیه
        emit Approval(msg.sender, _spender, _amount); // انتشار رویداد
        return true;
    }

    // Function to claim rewards
    function claimRewards() public whenNotPaused {
        require(balanceOf[msg.sender] > 0, "Insufficient balance to receive reward");
        transactionCount[msg.sender]++;

        if (transactionCount[msg.sender] % REWARD_THRESHOLD_1 == 0) {
            require(balanceOf[owner()] >= rewardAmount1, "Owner has insufficient balance for reward");
            balanceOf[owner()] = balanceOf[owner()].sub(rewardAmount1);
            balanceOf[msg.sender] = balanceOf[msg.sender].add(rewardAmount1);
            emit Transfer(owner(), msg.sender, rewardAmount1);
        }

        if (transactionCount[msg.sender] % REWARD_THRESHOLD_2 == 0) {
            require(balanceOf[owner()] >= rewardAmount2, "Owner has insufficient balance for reward");
            balanceOf[owner()] = balanceOf[owner()].sub(rewardAmount2);
            balanceOf[msg.sender] = balanceOf[msg.sender].add(rewardAmount2);
            emit Transfer(owner(), msg.sender, rewardAmount2);
        }

        if (transactionCount[msg.sender] % REWARD_THRESHOLD_4 == 0) {
            require(IERC20(ethContractAddress).balanceOf(address(this)) >= ethRewardAmount, "Insufficient ETH balance for reward");
            IERC20(ethContractAddress).safeTransfer(msg.sender, ethRewardAmount);
            emit EthReward(msg.sender, ethRewardAmount);
        }
        // Additional logic for higher reward thresholds can be added here
    }

    // Function to transfer tokens
    function transfer(address _to, uint256 _amount) public whenNotPaused {
        require(_to != address(0), "ERC20: transfer to the zero address");
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");
        require(!frozenAccount[msg.sender], "Account is frozen");
        require(!frozenAccount[_to], "Recipient account is frozen");

        // Limit daily transfers
        require(dailyTransferLimit == 0 || _amount <= dailyTransferLimit, "Transfer exceeds daily limit");

        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_amount);
        balanceOf[_to] = balanceOf[_to].add(_amount);
        emit Transfer(msg.sender, _to, _amount);   }

    // Function to transfer tokens from a specific account
    function transferFrom(address _from, address _to, uint256 _amount) public whenNotPaused {
        require(_from != address(0), "ERC20: transfer from the zero address");
        require(_to != address(0), "ERC20: transfer to the zero address");
        require(balanceOf[_from] >= _amount, "Insufficient balance");
        require(allowance[_from][msg.sender] >= _amount, "Insufficient allowance");
        require(!frozenAccount[_from], "Account is frozen");
        require(!frozenAccount[_to], "Recipient account is frozen");

        // Limit daily transfers
        require(dailyTransferLimit == 0 || _amount <= dailyTransferLimit, "Transfer exceeds daily limit");

        balanceOf[_from] = balanceOf[_from].sub(_amount);
        balanceOf[_to] = balanceOf[_to].add(_amount);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_amount);
        emit Transfer(_from, _to, _amount);
    }

    // Function to set the daily transfer limit
    function setDailyTransferLimit(uint256 _limit) public onlyOwner {
        dailyTransferLimit = _limit;
    }

    // Function to set the ETH contract address
    function setEthContractAddress(address _address) public onlyOwner {
        ethContractAddress = _address;
    }
}    