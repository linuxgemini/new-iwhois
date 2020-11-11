/**
 * Simple(?) WHOIS Client
 * @author linuxgemini
 * @license
 * Copyright 2020 İlteriş Yağıztegin Eroğlu (linuxgemini)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

"use strict";

const chardet = require("chardet");
const iconv = require("iconv-lite");
const net = require("net");

class whoisClient {
    constructor() {
        this.__extQuirks = require("./charset-list.json");
        this.__quirks = {
            "whois.ripe.net": "{{data}} -B",
            "whois.afrinic.net": "{{data}} -B",
        };
        this.__asnQuirks = {
            "whois.arin.net": "a {{data}}"
        };
    }

    /**
     * @param {string} str
     * @returns {string}
     */
    __strStrip(str) {
        const regexStart = /^\s+/;
        const regexEnd = /\s+$/;

        return str.replace(regexStart, "").replace(regexEnd, "");
    }

    /**
     * @param {string} data
     * @returns {string[]}
     */
    __returnRefers(data) {
        let splitter = (data.includes("\r\n") ? "\r\n" : "\n");
        let dataLines = data.split(splitter);

        /** @type {string[]} */
        let whoisServersRaw = [];

        /** @type {string[]} */
        let whoisServers = [];

        for (const line of dataLines) {
            if (line.startsWith("%") || line.startsWith("#")) continue;
            if (line.length === 0 || line.match(/^\s+$/)) continue;
            if (line.startsWith("refer:") || line.startsWith("whois:") || line.startsWith("ReferralServer:")) {
                let stripped = this.__strStrip(line.split(" ").slice(1).join(" "));
                whoisServersRaw.push(stripped);
            }
            if (this.__strStrip(line).match(/^\w+ WHOIS Server: /)) {
                let strippassone = this.__strStrip(line).replace(/^\w+ WHOIS Server: /, "");
                whoisServersRaw.push(strippassone);
            }
        }

        for (const index in whoisServersRaw) {
            let server = whoisServersRaw[index];
            if (server.startsWith("rwhois://")) continue;
            whoisServers.push(server.replace("whois://", ""));
        }

        return [...new Set(whoisServers)];
    }

    /**
     * @param {string} host
     * @param {string} querydata
     * @returns {Promise<string>}
     */
    __makeQuery(host, querydata) {
        return new Promise((resolve, reject) => {
            let data = Buffer.from([]);

            const client = new net.Socket();

            client.setTimeout(5000);

            client.on("data", (chunk) => {
                data = Buffer.concat([data, chunk]);
            });
    
            client.on("timeout", () => {
                return reject(new Error("Connection Timeout"));
            });
    
            client.on("error", (e) => {
                return reject(e);
            });
    
            client.on("close", (had_err) => {
                if (had_err) return reject(new Error("Connection closed with Error"));

                let encoding = (this.__extQuirks[host] ? this.__extQuirks[host].encoding : chardet.detect(data));
                return resolve(iconv.decode(data, encoding));
            });

            client.connect({
                host,
                port: 43
            }, () => {
                client.write(`${querydata}\r\n`);
            });
        });
    }

    /**
     * @param {string} host
     * @param {string} data
     */
    __quirkPass(host, data) {
        let quirkFixedData;
        if (this.__extQuirks[host]) quirkFixedData = this.__extQuirks[host].quirk.replace("{{data}}", data);
        if (this.__quirks[host]) quirkFixedData = this.__quirks[host].replace("{{data}}", (quirkFixedData || data));
        if (this.__asnQuirks[host] && data.match(/^AS\d{1,10}/i)) quirkFixedData = this.__asnQuirks[host].replace("{{data}}", (quirkFixedData || data).replace(/^AS/i, ""));

        return (quirkFixedData || data);
    }

    /**
     * @param {string} data
     * @param {number} recursed
     * @param {string} currHost
     */
    async queryRecursive(data, recursed = 0, currHost = "") {
        let host = (recursed > 0 ? currHost : "whois.iana.org");
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        let refs = this.__returnRefers(res);

        if (refs[0] && refs[0] !== host) {
            return await this.queryRecursive(data, (recursed + 1), refs[0]);
        } else {
            return res;
        }
    }

    async queryRIPE(data) {
        let host = "whois.ripe.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryARIN(data) {
        let host = "whois.arin.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryAFRINIC(data) {
        let host = "whois.afrinic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryAPNIC(data) {
        let host = "whois.apnic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryLACNIC(data) {
        let host = "whois.lacnic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }
}

module.exports = whoisClient;
