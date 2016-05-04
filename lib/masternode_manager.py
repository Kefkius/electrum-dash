from collections import namedtuple
import threading

import bitcoin
from blockchain import Blockchain
from masternode import MasternodeAnnounce, NetworkAddress
from util import AlreadyHaveAddress, print_error

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
        self.announce_event = threading.Event()
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

    def get_masternode_by_hash(self, hash_):
        for mn in self.masternodes:
            if mn.get_hash() == hash_:
                return mn

    def add_masternode(self, mn, save = True):
        """Add a new masternode."""
        self.masternodes.append(mn)
        if save:
            self.save()

    def remove_masternode(self, alias, save = True):
        """Remove the masternode labelled as alias."""
        mn = self.get_masternode(alias)
        # Don't delete the delegate key if another masternode uses it too.
        if not any(i.alias != mn.alias and i.delegate_key == mn.delegate_key for i in self.masternodes):
            address = bitcoin.public_key_to_bc_address(mn.delegate_key.decode('hex'))
            self.wallet.delete_masternode_delegate(address, save)

        self.masternodes.remove(mn)
        if save:
            self.save()

    def populate_masternode_output(self, alias):
        """Attempt to populate the masternode's data using its output."""
        mn = self.get_masternode(alias)
        if not mn:
            return
        txid = mn.vin.get('prevout_hash')
        prevout_n = mn.vin.get('prevout_n')
        if not txid or prevout_n is None:
            return
        # Return if it already has the information.
        if mn.collateral_key and mn.vin.get('address') and mn.vin.get('value') == 1000 * bitcoin.COIN:
            return

        tx = self.wallet.transactions.get(txid)
        if not tx:
            return
        if not tx.inputs:
            tx.deserialize()
        if len(tx.outputs) <= prevout_n:
            return
        _, addr, value = tx.outputs[prevout_n]
        mn.vin['address'] = addr
        mn.vin['value'] = value
        mn.vin['scriptSig'] = ''

        mn.collateral_key = self.wallet.get_public_keys(addr)[0]
        self.save()
        return True

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

    def get_delegate_pubkey(self, address):
        """Return the public key for address if we have it."""
        t = self.wallet.masternode_delegates.get(address)
        if t:
            return t[0]
        raise Exception('Delegate key not known: %s' % address)

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
            raise Exception('Masternode has already been activated')
        if not mn.collateral_key:
            raise Exception('Collateral key is not specified')
        if not mn.delegate_key:
            raise Exception('Masternode delegate key is not specified')
        if not mn.addr.ip:
            raise Exception('Masternode has no IP address')
        # Ensure that the masternode's vin is valid.
        if mn.vin.get('scriptSig') is None:
            mn.vin['scriptSig'] = ''
        if mn.vin.get('sequence') is None:
            mn.vin['sequence'] = 0xffffffff
        # Ensure that the masternode's last_ping is current.
        height = self.wallet.get_local_height() - 12
        header = self.wallet.network.get_header(height)
        mn.last_ping.block_hash = Blockchain.hash_header(header)
        mn.last_ping.vin = mn.vin

        # Sign ping with delegate key.
        address = bitcoin.public_key_to_bc_address(mn.delegate_key.decode('hex'))
        self.wallet.sign_masternode_ping(mn.last_ping, address, password)

        # After creating the Masternode Ping, sign the Masternode Announce.
        address = bitcoin.public_key_to_bc_address(mn.collateral_key.decode('hex'))
        mn.sig = self.wallet.sign_message(address, mn.serialize_for_sig(update_time=True), password)

        return mn

    def send_announce(self, alias):
        """Broadcast a Masternode Announce message for alias to the network.

        Returns a 2-tuple of (error_message, was_announced).
        """
        if not self.wallet.network:
            raise Exception('Not connected')

        mn = self.get_masternode(alias)
        # Vector-serialize the masternode.
        serialized = '01' + mn.serialize()
        errmsg = []
        callback = lambda r: self.broadcast_announce_callback(alias, errmsg, r)
        self.announce_event.clear()
        self.wallet.network.send([('blockchain.masternode.broadcast', [serialized])], callback)
        self.announce_event.wait()
        if errmsg:
            errmsg = errmsg[0]
        return (errmsg, mn.announced)

    def broadcast_announce_callback(self, alias, errmsg, r):
        """Callback for when a Masternode Announce message is broadcasted."""
        try:
            self.on_broadcast_announce(alias, r)
        except Exception as e:
            errmsg.append(str(e))
        finally:
            self.save()
            self.announce_event.set()

    def on_broadcast_announce(self, alias, r):
        """Validate the server response."""
        err = r.get('error')
        if err:
            raise Exception('Error response: %s' % str(err))

        result = r.get('result')

        mn = self.get_masternode(alias)
        mn_hash = mn.get_hash()
        mn_dict = result.get(mn_hash)
        if not mn_dict:
            raise Exception('No result for expected Masternode Hash. Got %s' % result)

        if mn_dict.get('errorMessage'):
            raise Exception('Announce was rejected: %s' % mn_dict['errorMessage'])
        if mn_dict.get(mn_hash) != 'successful':
            raise Exception('Announce was rejected (no error message specified)')

        mn.announced = True

    def import_masternode_conf_lines(self, conf_lines, password):
        """Import a list of MasternodeConfLine."""
        def already_have(line):
            for masternode in self.masternodes:
                # Don't let aliases collide.
                if masternode.alias == line.alias:
                    return True
                # Don't let outputs collide.
                if masternode.vin.get('prevout_hash') == line.txid and masternode.vin.get('prevout_n') == line.output_index:
                    return True
            return False

        num_imported = 0
        for conf_line in conf_lines:
            if already_have(conf_line):
                continue
            # Import delegate WIF key for signing last_ping.
            try:
                address = self.wallet.import_masternode_delegate(conf_line.wif, password)
            except AlreadyHaveAddress as e:
                address = e.addr
            public_key = bitcoin.public_key_from_private_key(conf_line.wif)

            addr = conf_line.addr.split(':')
            addr = NetworkAddress(ip=addr[0], port=int(addr[1]))
            vin = {'prevout_hash': conf_line.txid, 'prevout_n': conf_line.output_index}
            mn = MasternodeAnnounce(alias=conf_line.alias, vin=vin,  
                    delegate_key = public_key, addr=addr)
            self.add_masternode(mn)
            try:
                self.populate_masternode_output(mn.alias)
            except Exception as e:
                print_error(str(e))
            num_imported += 1

        return num_imported
