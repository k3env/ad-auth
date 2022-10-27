import { authenticate } from 'ldap-authentication';

export async function auth(aduser, adpass) {
  const connector = {
    user: process.env.CONNECTOR_USER,
    pass: process.env.CONNECTOR_PASS,
    dn: process.env.CONNECTOR_DN,
  };
  const domain = process.env.DOMAIN;
  const orgunits = [];

  const domparts = domain.split('.');

  const upnuser = aduser + '@' + domain;

  const dn = domparts.map((dc) => `DC=${dc}`).join(',');
  const ou = orgunits.map((ou) => `OU=${ou}`).join(',');

  const search = ou === '' ? dn : [ou, dn].join(',');

  const user = await authenticate({
    ldapOpts: { url: `ldap://${process.env.AD_SERVER}` },
    adminDn: `CN=${connector.user},${connector.dn}`,
    adminPassword: connector.pass,
    userPassword: adpass,
    userSearchBase: search,
    usernameAttribute: 'userPrincipalName',
    username: upnuser,
  });

  if (user === undefined) {
    throw new Error('Provided credentials are invalid');
  }
  return {
    displayName: user.cn,
    userName: user.userPrincipalName,
    groups: user.memberOf.map((_g) => _g.split(',')[0].split('=')[1]),
    flags: uacFlags(user.userAccountControl),
  };
}

export function uacFlags(uacvalue) {
  const flags = {
    SCRIPT: false,
    ACCOUNTDISABLE: false,
    HOMEDIR_REQUIRED: false,
    LOCKOUT: false,
    PASSWD_NOTREQD: false,
    PASSWD_CANT_CHANGE: false,
    ENCRYPTED_TEXT_PWD_ALLOWED: false,
    TEMP_DUPLICATE_ACCOUNT: false,
    NORMAL_ACCOUNT: false,
    INTERDOMAIN_TRUST_ACCOUNT: false,
    WORKSTATION_TRUST_ACCOUNT: false,
    SERVER_TRUST_ACCOUNT: false,
    DONT_EXPIRE_PASSWORD: false,
    MNS_LOGON_ACCOUNT: false,
    SMARTCARD_REQUIRED: false,
    TRUSTED_FOR_DELEGATION: false,
    NOT_DELEGATED: false,
    USE_DES_KEY_ONLY: false,
    DONT_REQ_PREAUTH: false,
    PASSWORD_EXPIRED: false,
    TRUSTED_TO_AUTH_FOR_DELEGATION: false,
    PARTIAL_SECRETS_ACCOUNT: false,
  };

  if (uacvalue % 0x04000000 < uacvalue) {
    uacvalue -= 0x04000000;
    flags.PARTIAL_SECRETS_ACCOUNT = true;
  }
  if (uacvalue % 0x1000000 < uacvalue) {
    uacvalue -= 0x1000000;
    flags.TRUSTED_TO_AUTH_FOR_DELEGATION = true;
  }
  if (uacvalue % 0x800000 < uacvalue) {
    uacvalue -= 0x800000;
    flags.PASSWORD_EXPIRED = true;
  }
  if (uacvalue % 0x400000 < uacvalue) {
    uacvalue -= 0x400000;
    flags.DONT_REQ_PREAUTH = true;
  }
  if (uacvalue % 0x200000 < uacvalue) {
    uacvalue -= 0x200000;
    flags.USE_DES_KEY_ONLY = true;
  }
  if (uacvalue % 0x100000 < uacvalue) {
    uacvalue -= 0x100000;
    flags.NOT_DELEGATED = true;
  }
  if (uacvalue % 0x80000 < uacvalue) {
    uacvalue -= 0x80000;
    flags.TRUSTED_FOR_DELEGATION = true;
  }
  if (uacvalue % 0x40000 < uacvalue) {
    uacvalue -= 0x40000;
    flags.SMARTCARD_REQUIRED = true;
  }
  if (uacvalue % 0x20000 < uacvalue) {
    uacvalue -= 0x20000;
    flags.MNS_LOGON_ACCOUNT = true;
  }
  if (uacvalue % 0x10000 < uacvalue) {
    uacvalue -= 0x10000;
    flags.DONT_EXPIRE_PASSWORD = true;
  }
  if (uacvalue % 0x2000 < uacvalue) {
    uacvalue -= 0x2000;
    flags.SERVER_TRUST_ACCOUNT = true;
  }
  if (uacvalue % 0x1000 < uacvalue) {
    uacvalue -= 0x1000;
    flags.WORKSTATION_TRUST_ACCOUNT = true;
  }
  if (uacvalue % 0x0800 < uacvalue) {
    uacvalue -= 0x0800;
    flags.INTERDOMAIN_TRUST_ACCOUNT = true;
  }
  if (uacvalue % 0x0200 < uacvalue) {
    uacvalue -= 0x0200;
    flags.NORMAL_ACCOUNT = true;
  }
  if (uacvalue % 0x0100 < uacvalue) {
    uacvalue -= 0x0100;
    flags.TEMP_DUPLICATE_ACCOUNT = true;
  }
  if (uacvalue % 0x0080 < uacvalue) {
    uacvalue -= 0x0080;
    flags.ENCRYPTED_TEXT_PWD_ALLOWED = true;
  }
  if (uacvalue % 0x0040 < uacvalue) {
    uacvalue -= 0x0040;
    flags.PASSWD_CANT_CHANGE = true;
  }
  if (uacvalue % 0x0020 < uacvalue) {
    uacvalue -= 0x0020;
    flags.PASSWD_NOTREQD = true;
  }
  if (uacvalue % 0x0010 < uacvalue) {
    uacvalue -= 0x0010;
    flags.LOCKOUT = true;
  }
  if (uacvalue % 0x0008 < uacvalue) {
    uacvalue -= 0x0008;
    flags.HOMEDIR_REQUIRED = true;
  }
  if (uacvalue % 0x0002 < uacvalue) {
    uacvalue -= 0x0002;
    flags.ACCOUNTDISABLE = true;
  }
  if (uacvalue % 0x0001 < uacvalue) {
    uacvalue -= 0x0001;
    flags.SCRIPT = true;
  }

  return flags;
}
