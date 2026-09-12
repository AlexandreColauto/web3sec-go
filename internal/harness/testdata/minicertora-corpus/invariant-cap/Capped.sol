// Task 12: the sound twin of `invariant-cap-broken` — the same invariant, with
// `setCap` guarded so that no call can leave `cap` below `total`.
contract Capped {
    uint256 public total;
    uint256 public cap;

    constructor() {
        cap = 100;
    }

    function deposit(uint256 x) public {
        require(total + x <= cap);
        total = total + x;
    }

    function setCap(uint256 c) public {
        require(c >= total);
        cap = c;
    }
}
