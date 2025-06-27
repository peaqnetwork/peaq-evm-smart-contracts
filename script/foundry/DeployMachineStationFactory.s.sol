// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {MachineStationFactory} from "../../src/machine-station/MachineStationFactory.sol";

contract DeployGasStation is Script {
    function run() external returns (MachineStationFactory) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        address adminAddress = vm.envAddress("ADMIN_ADDRESS");

        address stationManager = vm.envAddress("STATION_MANAGER_ADDRESS");
        uint256 _txRefundAmount = uint256(vm.envInt("TX_REFUND_AMOUNT"));

        vm.startBroadcast(deployerPrivateKey);

        MachineStationFactory factory = new MachineStationFactory(adminAddress, stationManager, _txRefundAmount);

        vm.stopBroadcast();

        console.log("MachineStationFactory deployed to:", address(factory));
        console.log("Admin address:", adminAddress);
        console.log("Station Manager address:", stationManager);

        return factory;
    }
}
