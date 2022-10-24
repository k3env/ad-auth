import { authenticate } from 'ldap-authentication'
import * as dotenv from 'dotenv'
import * as readline from "readline";

dotenv.config()

const echo = console.log;

const connector = {
    user: process.env.CONNECTOR_USER,
    pass: process.env.CONNECTOR_PASS,
    dn: process.env.CONNECTOR_DN
}

const rli = readline.createInterface({input: process.stdin, output: process.stdout});

rli.question('username ', (a) => {
    const user = a;
    rli.question('password ', (p) => {
        const pass = p;
        const domain = process.env.DOMAIN;
        const orgunits = [];

        const domparts = domain.split('.');

        const upnuser = user + "@" + domain;

        const dn = domparts.map((dc) => `DC=${dc}`).join(',');
        const ou = orgunits.map((ou) => `OU=${ou}`).join(',');

        const search = ou === '' ? dn : [ou,dn].join(',');

        authenticate({
            ldapOpts: { url: `ldap://${process.env.AD_SERVER}` },
            adminDn: `CN=${connector.user},${connector.dn}`, //"CN=connector-7300f7c2,CN=Builtin,DC=BS,DC=local",
            adminPassword: connector.pass,
            userPassword: pass,
            userSearchBase: search,
            usernameAttribute: 'userPrincipalName',
            username: upnuser,
        })
        .catch((r) => { echo('Error:', r.message); })
        .then((v) => {
            const _user = {
                displayName: v.cn,
                groups: v.memberOf.map((v) => v.split(',')[0].split('=')[1])
            }
    echo(_user);
        })

    })
})

