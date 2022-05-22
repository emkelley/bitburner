/** @param {NS} ns */
export async function main(ns) {
  const target = ns.args[0];

  if (ns.fileExists("BruteSSH.exe", "home")) ns.brutessh(target);
  if (ns.fileExists("FTPCrack.exe", "home")) ns.ftpcrack(target);
  if (ns.fileExists("NUKE.exe", "home")) ns.nuke(target);
}
