"use strict";

const fs = require("fs");
const https = require("https");

// Modified code from StackOverflow
// https://stackoverflow.com/questions/53963608/syntax-for-post-using-promisifyhttps
const getServList = () => {
    return new Promise((resolve, reject) => {
        let data = Buffer.from([]);

        const req = https.get("https://raw.githubusercontent.com/rfc1036/whois/next/tld_serv_list", r => {
            r.on("data", (chunk) => {
                data = Buffer.concat([data, chunk]);
            });

            r.on("timeout", () => {
                return reject(new Error("Connection Timeout"));
            });

            r.on("end", (res) => {
                if (res.statusCode === 200) {
                    resolve(data.toString("utf8"));
                } else {
                    reject(new Error("Response indicated failure"));
                }
            });
        }).on("error", (err) => {
            reject(err);
        });

        req.end();
    });
};

const main = async () => {
    let masterlisttsv = await getServList();
    let finale = {};

    for (const line of masterlisttsv.split("\n")) {
        if (line.startsWith("#")) continue;
        let sp = line.split(/\s+/g);
        if (sp[0] === "" || sp.length === 0) continue;
        if (sp[1] !== "WEB" && sp[1] !== "NONE" && sp[1] !== "AFILIAS" && sp[1] !== "VERISIGN" && sp[1] !== "ARPA" && sp[1] !== "IP6") finale[sp[0]] = sp[1];
    }

    fs.writeFileSync("../domain-whois-list.json", JSON.stringify(finale, null, 4));
};

main();