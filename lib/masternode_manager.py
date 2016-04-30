from collections import namedtuple

import bitcoin
from masternode import MasternodeAnnounce, NetworkAddress

MasternodeConfLine = namedtuple('MasternodeConfLine', ('alias', 'addr',
        'wif', 'txid', 'output_index'))

def parse_masternode_conf(lines):
    """Construct MasternodeConfLine instances from lines of a masternode.conf file."""
    conf_lines = []
    for line in lines:
        # Comment.
        if line.startswith('#'):
            continue

        s = line.split(' ')
        if len(s) < 5:
            continue
        alias = s[0]
        addr_str = s[1]
        masternode_wif = s[2]
        collateral_txid = s[3]
        collateral_output_n = s[4]

        # Validate input.
        try:
            key_valid = bitcoin.ASecretToSecret(masternode_wif)
            assert key_valid
        except Exception:
            raise ValueError('Invalid masternode private key of alias "%s"' % alias)

        if len(collateral_txid) != 64:
            raise ValueError('Transaction ID of alias "%s" must be 64 hex characters.' % alias)

        try:
            collateral_output_n = int(collateral_output_n)
        except ValueError:
            raise ValueError('Transaction output index of alias "%s" must be an integer.' % alias)

        conf_lines.append(MasternodeConfLine(alias, addr_str, masternode_wif, collateral_txid, collateral_output_n))
    return conf_lines

class MasternodeManager(object):
    """Masternode manager.

    Keeps track of masternodes and helps with signing broadcasts.
    """
    def __init__(self, wallet, config):
        self.wallet = wallet
        self.config = config
        self.load()

    def load(self):
        """Load masternodes from wallet storage."""
        masternodes = self.wallet.storage.get('masternodes', {})
        self.masternodes = [MasternodeAnnounce.from_dict(d) for d in masternodes.values()]

    def get_masternode(self, alias):
        """Get the masternode labelled as alias."""
        for mn in self.masternodes:
            if mn.alias == alias:
                return mn

    def add_masternode(self, mn, save = True):
        """Add a new masternode."""
        self.masternodes.append(mn)
        if save:
            self.save()

    def remove_masternode(self, alias, save = True):
        """Remove the masternode labelled as alias."""
        mn = self.get_masternode(alias)
        self.masternodes.remove(mn)
        if save:
            self.save()

    def get_masternode_outputs(self, domain = None, exclude_frozen = True):
        """Get spendable coins that can be used as masternode collateral."""
        coins = self.wallet.get_spendable_coins(domain = domain, exclude_frozen = exclude_frozen)

        used_vins = map(lambda mn: '%s:%d' % (mn.vin.get('prevout_hash'), mn.vin.get('prevout_n', 0xffffffff)), self.masternodes)
        unused = lambda d: '%s:%d' % (d['prevout_hash'], d['prevout_n']) not in used_vins
        correct_amount = lambda d: d['value'] == 1000 * bitcoin.COIN

        # Valid outputs have a value of exactly 1000 DASH and
        # are not in use by an existing masternode.
        is_valid = lambda d: correct_amount(d) and unused(d)

        coins = filter(is_valid, coins)
        return coins

    def save(self):
        """Save masternodes."""
        masternodes = {}
        for mn in self.masternodes:
            masternodes[mn.alias] = mn.dump()

        self.wallet.storage.put('masternodes', masternodes)

    def sign_announce(self, alias, password):
        """Sign a Masternode Announce message for alias."""
        mn = self.get_masternode(alias)
        if not mn:
            raise Exception('Nonexistent masternode')
        if mn.announced:
            raise Exception('Masternode has already activated')
        # Ensure that the masternode's last_ping is current.
        mn.last_ping.retrieve_block_hash(self.wallet)
        mn.last_ping.network_event.wait()
        mn.last_ping.vin = mn.vin

        # Sign ping with delegate key.
        address = bitcoin.public_key_to_bc_address(mn.delegate_key.decode('hex'))
        mn.last_ping.sig = self.wallet.sign_message(address, mn.last_ping.serialize_for_sig(update_time=True), password)

        # After creating the Masternode Ping, sign the Masternode Announce.
        address = bitcoin.public_key_to_bc_address(mn.collateral_key.decode('hex'))
        mn.sig = self.wallet.sign_message(address, mn.serialize_for_sig(update_time=True), password)

        return mn

    def send_announce(self, alias):
        """Broadcast a Masternode Announce message for alias to the network."""
        if not self.wallet.network:
            raise Exception('Not connected')
        raise NotImplementedError()

        mn = self.get_masternode(alias)
        serialized = mn.serialize()
        self.wallet.network.send('masternode.announce.broadcast', [serialized], self.on_broadcast_announce)

    # TODO: determine format of result.
    def on_broadcast_announce(self, r):
        """Callback for when a Masternode Announce message is broadcasted."""
        result = r.get('result')
        # The result may be a JSON dict?
        # Assume raw is the serialized masternode.
        raw = ''
        mn_ = MasternodeAnnounce.deserialize(raw)
        alias = mn_.alias
        mn = self.get_masternode(alias)
        mn.announced = True
        self.save()

    def import_masternode_conf_lines(self, conf_lines, password):
        """Import a list of MasternodeConfLine."""
        for conf_line in conf_lines:
            # Import delegate WIF key for signing last_ping.
            address = self.wallet.import_key(conf_line.wif, password)
            public_key = bitcoin.public_key_from_private_key(conf_line.wif)

            addr = conf_line.addr.split(':')
            addr = NetworkAddress(ip=addr[0], port=int(addr[1]))
            vin = {'prevout_hash': conf_line.txid, 'prevout_n': 'output_index'}
            mn = MasternodeAnnounce(alias=conf_line.alias, vin=vin,  
                    delegate_key = public_key, addr=addr)
            self.add_masternode(mn)
