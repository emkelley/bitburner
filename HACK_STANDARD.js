/** @param {NS} ns */
export const main = async (ns) => {
  const [target] = ns.args;

  const serverSec = ns.getServerSecurityLevel(target);
  const serverMinSec = ns.getServerMinSecurityLevel(target);
  const serverMoney = ns.getServerMoneyAvailable(target);
  const moneyThreshold = ns.getServerMaxMoney(target) * 0.75;
  const secThreshold = serverMinSec + 5;

  while (true) {
    // If the target's security level is higher than this, weaken it before doing anything else
    if (serverSec > secThreshold) await ns.weaken(target);
    // Make sure the server has enough money to be worth hacking
    else if (serverMoney < moneyThreshold) await ns.grow(target);
    // Hack
    else await ns.hack(target);
  }
};
