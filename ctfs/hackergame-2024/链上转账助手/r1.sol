// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Receiver {
    uint256 public totalReceived;
    mapping(address => uint256) public balances;


    fallback() external payable {
        totalReceived += msg.value;
    }
}


