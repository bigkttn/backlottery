import express, { Response } from "express";
import { app } from "./app";
import * as os from "os";

const port = 3000;

app.use(express.json());



const ip: string = (() => {
    let address = "0.0.0.0";
    const interfaces = os.networkInterfaces();

    Object.keys(interfaces).forEach((interfaceName) => {
        interfaces[interfaceName]?.forEach((interfaceInfo) => {
            if (interfaceInfo.family === "IPv4" && !interfaceInfo.internal) {
                address = interfaceInfo.address;
            }
        });
    });

    return address;
})();

app.listen(port, () => {
    console.log(`Trip booking API listening at http://${ip}:${port}`);
});