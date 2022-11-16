# Wood-Pole-Vibration-Monitor-Bluetooth-IOT-Design


This repository contains the code used to program Nucleo-WB15CC devices using Bluetooth Low Energy


To replicate the experiments, the STMCubeIDE projects work for all three experiments. Copy the app_ble.c code into the respective project then build & debug to load onto STM32WB15cc board.

In the app_ble.c files the noteworthy functions are: Scan_Request, Adv_Request, Adv_Cancel, SVCCTL_App_Notification & APP_BLE_Init.
