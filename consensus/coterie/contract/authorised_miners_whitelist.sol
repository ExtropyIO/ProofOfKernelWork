pragma solidity ^0.4.17;

contract AuthorisedMinersWhitelist {

    mapping(address => bool) whitelist;

    function isAuthorisedMiner(address miner) public view returns (bool) {
        return whitelist[miner];
    }

    function authoriseMiner(address miner) public {
        whitelist[miner] = true;
    }

    function removeMinersAuthorisation(address miner) public {
        whitelist[miner] = false;
    }
}