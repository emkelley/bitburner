/** @param {NS} ns **/
export async function main(ns) {
  /* Pwn and hack servers that are currently hackable.*/
  const bruteSSH = ns.fileExists("BruteSSH.exe");
  const ftpCrack = ns.fileExists("FTPCrack.exe");
  const relaySMTP = ns.fileExists("relaySMTP.exe");
  const httpWorm = ns.fileExists("HTTPWorm.exe");
  const sqlInject = ns.fileExists("SQLInject.exe");

  let portTakers = 0;
  if (bruteSSH) portTakers++;
  if (ftpCrack) portTakers++;
  if (relaySMTP) portTakers++;
  if (httpWorm) portTakers++;
  if (sqlInject) portTakers++;

  const serverCheck = (target) => {
    let maxRAM = ns.getServerMaxRam(target);
    let isRooted = ns.hasRootAccess(target);
    let reqHack = ns.getServerRequiredHackingLevel(target);
    let minSec = ns.getServerMinSecurityLevel(target);
    let maxMoney = ns.getServerMaxMoney(target);
    return [target, maxRAM, isRooted, reqHack, minSec, maxMoney];
  };

  const pwn = (target) => {
    if (bruteSSH) ns.brutessh(target);
    if (ftpCrack) ns.ftpcrack(target);
    if (relaySMTP) ns.relaysmtp(target);
    if (httpWorm) ns.httpworm(target);
    if (sqlInject) ns.sqlinject(target);
    ns.nuke(target);
  };

  const hostname = "home";
  const script = "HACK_STANDARD.js";

  let script_args = [];
  let servers = serverCheck(hostname);
  let scanned = [hostname];
  let scanner2 = [];
  let scanner3 = [];
  let scanner = ns.scan(hostname);
  let checkme = 1;
  let rootable = [];
  let earnable = [];

  ns.tprint(servers);

  /* As long as there's something to scan, scan*/
  while (checkme > 0) {
    /* Loop through the SCANNER object, scanning identified servers..*/
    for (i in scanner.length) {
      /* If the server isn't in the SERVERS list, scan it, add it to the scanned list. */
      if (servers.indexOf(scanner[i]) == -1) {
        servers.push(serverCheck(scanner[i]));
        if (
          ns.getServerMaxMoney(scanner[i]) > 0 &&
          ns.getServerRequiredHackingLevel(scanner[i]) <= ns.getHackingLevel()
        )
          earnable.push(scanner[i]);
        if (
          ns.getServerNumPortsRequired(scanner[i]) <= portTakers &&
          !ns.hasRootAccess(scanner[i])
        )
          rootable.push(scanner[i]);
        let scanner2 = ns.scan(scanner[i]);
        /* Check the scan results just retrieved to see if they are unique, and if they've already been scanned.  */
        for (i2 in scanner2.length) {
          if (scanned.indexOf(scanner2[i2]) == -1) {
            scanner3.push(scanner2[i2]);
          }
        }
        scanned.push(scanner[i]);
      }
    }
    scanner = scanner3;
    scanner3 = [];
    checkme = scanner.length;
  }

  for (i in rootable.length) {
    pwn(rootable[i]);
    var maxThreads = Math.floor(
      (ns.getServerMaxRam(rootable[i]) - ns.getServerUsedRam(rootable[i])) /
        ns.getScriptRam("HACK_STANDARD.js")
    );
    var generalThreads = Math.floor(maxThreads / earnable.length);
    var bonusServers = maxThreads % earnable.length;
    ns.tprint(`Max Threads on server:  ${rootable[i]} ${maxThreads}`);
    ns.tprint(
      `Earnable servers - ${
        earnable.length - bonusServers
      }@${generalThreads} with ${bonusServers}@${generalThreads + 1}`
    );
    await ns.scp(script, ns.getHostname(), rootable[i]);
    for (r in earnable.length) {
      var targetMax = ns.getServerMaxMoney(earnable[r]);
      var targetMin = ns.getServerMinSecurityLevel(earnable[r]);
      script_args[0] = earnable[r];
      script_args[1] = targetMax;
      script_args[2] = targetMin;
      if (r < bonusServers) {
        ns.tprint(
          `Launching script '${script}' on server '${rootable[i]}' with ${
            generalThreads + 1
          } threads and the following arguments: ${script_args}`
        );
        ns.exec(script, rootable[i], generalThreads + 1, ...script_args);
        ns.tprint(`${earnable[r]}@${generalThreads + 1} threads`);
      } else if (generalThreads > 0) {
        ns.tprint(
          `Launching script '${script}' on server '${rootable[i]}' with ${generalThreads} threads and the following arguments: ${script_args}`
        );
        ns.exec(script, rootable[i], generalThreads, ...script_args);
        ns.tprint(`${earnable[r]}@${generalThreads + 1} threads`);
      }
    }
  }

  ns.tprint("Summary results:");
  ns.tprint(`Unique hits to scan: ${scanner3}`);
  ns.tprint(`Last Scan results: ${scanner2}`);
  ns.tprint("Servers Scanned (nameonly): " + scanned);
  ns.tprint("Rootable Server names: " + rootable);
  ns.tprint("Earnable Server names: " + earnable);
  ns.toast(`${rootable.length} Rootable servers identified.`, "success", 10000);
  ns.toast(`${earnable.length} Earnable servers identified.`, "success", 10000);
  ns.tprint("Ended");
}
