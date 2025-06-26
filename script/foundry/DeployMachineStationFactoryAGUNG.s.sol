// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {MachineStationFactory} from "../../src/machine-station/MachineStationFactory.sol";

contract DeployGasStation is Script {
    function run() external returns (MachineStationFactory) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        address adminAddress = vm.envAddress("ADMIN_ADDRESS");
        uint256 adminPrivateKey = vm.envUint("ADMIN_PRIVATE_KEY");


        address stationManager = vm.envAddress("STATION_MANAGER_ADDRESS");
        // Uncomment below if you want to use the stationManager account to update the configs
        // uint256 stationManagerPrivateKey = vm.envUint("STATION_MANAGER_PRIVATE_KEY");


        uint256 _txRefundAmount = uint256(vm.envInt("TX_REFUND_AMOUNT"));


        bytes32 minBalanceKey = keccak256(abi.encodePacked(vm.envString("MIN_BALANCE_KEY")));
        uint256 minBalanceValueAgung = uint256(vm.envInt("MIN_BALANCE_VALUE_AGUNG"));

        bytes32 fundingAmountKey = keccak256(abi.encodePacked(vm.envString("FUNDING_AMOUNT_KEY")));
        uint256 fundingAmountKeyAgung = uint256(vm.envInt("FUNDING_AMOUNT_VALUE_AGUNG"));

        // Deploy contract with deployer account
        vm.startBroadcast(deployerPrivateKey);
        MachineStationFactory factory = new MachineStationFactory(adminAddress, stationManager, _txRefundAmount);
        vm.stopBroadcast();

        // Update configs with admin or stationManager account using the private key
        vm.startBroadcast(adminPrivateKey);
        factory.updateConfigs(minBalanceKey, minBalanceValueAgung);
        factory.updateConfigs(fundingAmountKey, fundingAmountKeyAgung);
        vm.stopBroadcast();

        console.log("MachineStationFactory deployed to:", address(factory));
        console.log("Admin address:", adminAddress);
        console.log("Station Manager address:", stationManager);

        return factory;
    }
}
