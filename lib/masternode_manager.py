from collections import namedtuple, OrderedDict
import base64
import threading

import bitcoin
from blockchain import Blockchain
from masternode import MasternodeAnnounce, NetworkAddress
from masternode_budget import BudgetProposal, BudgetVote
from util import AlreadyHaveAddress, print_error
from util import format_satoshis_plain

BUDGET_FEE_CONFIRMATIONS = 6
BUDGET_FEE_TX = 5 * bitcoin.COIN
# From masternode.h
MASTERNODE_MIN_CONFIRMATIONS = 15

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
        # Cache of proposal hashes.
        # Used when retrieving the hash of a proposal.
        self.proposal_hash_cache = OrderedDict()
        self.network_event = threading.Event()
        self.wallet = wallet
        self.config = config
        # List of all proposals on the network.
        self.all_proposals = []
        # Subscribed masternode statuses.
        self.masternode_statuses = {}

        self.load()

    def load(self):
        """Load masternodes from wallet storage."""
        masternodes = self.wallet.storage.get('masternodes', {})
        self.masternodes = [MasternodeAnnounce.from_dict(d) for d in masternodes.values()]
        proposals = self.wallet.storage.get('budget_proposals', {})
        self.proposals = [BudgetProposal.from_dict(d) for d in proposals.values()]
        self.budget_votes = [BudgetVote.from_dict(d) for d in self.wallet.storage.get('budget_votes', [])]

    def send_subscriptions(self):
        if not self.wallet.network:
            return
        self.subscribe_to_masternodes()
        self.subscribe_to_proposals()

    def subscribe_to_masternodes(self):
        for mn in self.masternodes:
            if not mn.announced:
                continue
            collateral = mn.get_collateral_str()
            if self.masternode_statuses.get(collateral) is None:
                req = ('masternode.subscribe', [collateral])
                self.wallet.network.send([req], self.masternode_subscription_response)
                self.masternode_statuses[collateral] = ''

    def subscribe_to_proposals(self):
        req = ('masternode.proposals.subscribe', [])
        self.wallet.network.send([req], self.proposals_subscription_response)

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
        if any(i.alias == mn.alias for i in self.masternodes):
            raise Exception('A masternode with alias "%s" already exists' % mn.alias)
        self.masternodes.append(mn)
        if save:
            self.save()

    def remove_masternode(self, alias, save = True):
        """Remove the masternode labelled as alias."""
        mn = self.get_masternode(alias)
        if not mn:
            raise Exception('Nonexistent masternode')
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
        if mn.announced:
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

    def check_can_sign_masternode(self, alias):
        """Raise an exception if alias can't be signed and announced to the network."""
        mn = self.get_masternode(alias)
        if not mn:
            raise Exception('Nonexistent masternode')
        if not mn.collateral_key:
            raise Exception('Collateral key is not specified')
        if not mn.delegate_key:
            raise Exception('Masternode delegate key is not specified')
        if not mn.addr.ip:
            raise Exception('Masternode has no IP address')

        # Ensure that the collateral payment has >= MASTERNODE_MIN_CONFIRMATIONS.
        confirmations, _ = self.wallet.get_confirmations(mn.vin['prevout_hash'])
        if confirmations < MASTERNODE_MIN_CONFIRMATIONS:
            raise Exception('Collateral payment must have at least %d confirmations (current: %d)' % (MASTERNODE_MIN_CONFIRMATIONS, confirmations))
        # Ensure that the masternode's vin is valid.
        if mn.vin.get('value', 0) != bitcoin.COIN * 1000:
            raise Exception('Masternode requires a collateral 1000 DASH output.')

        # If the masternode has been announced, it can be announced again if it has been disabled.
        if mn.announced:
            status = self.masternode_statuses.get(mn.get_collateral_str())
            if status in ['PRE_ENABLED', 'ENABLED']:
                raise Exception('Masternode has already been activated')

    def save(self):
        """Save masternodes."""
        masternodes = {}
        for mn in self.masternodes:
            masternodes[mn.alias] = mn.dump()
        proposals = {p.get_hash(): p.dump() for p in self.proposals}
        votes = [v.dump() for v in self.budget_votes]

        self.wallet.storage.put('masternodes', masternodes)
        self.wallet.storage.put('budget_proposals', proposals)
        self.wallet.storage.put('budget_votes', votes)

    def sign_announce(self, alias, password):
        """Sign a Masternode Announce message for alias."""
        self.check_can_sign_masternode(alias)
        mn = self.get_masternode(alias)
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
        self.network_event.clear()
        self.wallet.network.send([('masternode.announce.broadcast', [serialized])], callback)
        self.network_event.wait()
        self.subscribe_to_masternodes()
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
            self.network_event.set()

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



    def get_votes(self, alias):
        """Get budget votes that alias has cast."""
        mn = self.get_masternode(alias)
        if not mn:
            raise Exception('Nonexistent masternode')
        return filter(lambda v: v.vin == mn.vin, self.budget_votes)

    def vote(self, alias, proposal_name, vote_choice, password):
        """Vote on a budget proposal."""
        if not self.wallet.network:
            raise Exception('Not connected')
        # Validate vote choice.
        if vote_choice.upper() not in ('YES', 'NO'):
            raise ValueError('Invalid vote choice: "%s"' % vote_choice)

        # Retrieve the proposal hash from the network if we don't have it.
        proposal = self.get_proposal(proposal_name)
        if not proposal:
            proposal_hash = self.retrieve_proposal_hash(proposal_name)
        else:
            proposal_hash = proposal.get_hash()
        # Make sure we haven't already voted.
        votes = self.get_votes(alias)
        if any(v.proposal_hash == proposal_hash for v in votes):
            raise Exception('Alias "%s" has already voted for proposal "%s"' % (alias, proposal_name))

        # Create the vote.
        mn = self.get_masternode(alias)
        vote = BudgetVote(vin=mn.vin, proposal_hash=proposal_hash, vote=vote_choice)

        # Sign the vote with delegate key.
        address = bitcoin.public_key_to_bc_address(mn.delegate_key.decode('hex'))
        sig = self.wallet.sign_budget_vote(vote, address, password)

        return self.send_vote(vote, base64.b64encode(sig))

    def send_vote(self, vote, sig):
        """Broadcast vote to the network.

        Returns a 2-tuple of (error_message, success).
        """
        errmsg = []
        callback = lambda r: self.broadcast_vote_callback(vote, errmsg, r)
        params = [vote.vin['prevout_hash'], vote.vin['prevout_n'], vote.proposal_hash, vote.vote.lower(),
                vote.timestamp, sig]
        self.network_event.clear()
        self.wallet.network.send([('masternode.budget.submitvote', params)], callback)
        self.network_event.wait()
        if errmsg:
            return (errmsg[0], False)
        return (errmsg, True)

    def broadcast_vote_callback(self, vote, errmsg, r):
        """Callback for when a vote is broadcast."""
        if r.get('error'):
            errmsg.append(r['error'])
        else:
            self.budget_votes.append(vote)
            self.save()

        self.network_event.set()



    def get_proposal(self, name):
        for proposal in self.proposals:
            if proposal.proposal_name == name:
                return proposal

    def add_proposal(self, proposal, save = True):
        """Add a new proposal."""
        if proposal in self.proposals:
            raise Exception('Proposal already exists')
        self.proposals.append(proposal)
        if save:
            self.save()

    def remove_proposal(self, proposal_name, save = True):
        """Remove the proposal named proposal_name."""
        proposal = self.get_proposal(proposal_name)
        if not proposal:
            raise Exception('Proposal does not exist')
        self.proposals.remove(proposal)
        if save:
            self.save()

    def create_proposal_tx(self, proposal_name, password, save = True):
        """Create a fee transaction for proposal_name."""
        proposal = self.get_proposal(proposal_name)
        if proposal.fee_txid:
            print_error('Warning: Proposal "%s" already has a fee tx: %s' % (proposal_name, proposal.fee_txid))
        if proposal.submitted:
            raise Exception('Proposal has already been submitted')

        h = bitcoin.hash_decode(proposal.get_hash()).encode('hex')
        script = '6a20' + h # OP_RETURN hash
        outputs = [('script', script.decode('hex'), BUDGET_FEE_TX)]
        tx = self.wallet.mktx(outputs, password, self.config)
        proposal.fee_txid = tx.hash()
        if save:
            self.save()
        return tx

    def submit_proposal(self, proposal_name, save = True):
        """Submit the proposal for proposal_name."""
        proposal = self.get_proposal(proposal_name)
        if not proposal.fee_txid:
            raise Exception('Proposal has no fee transaction')
        if proposal.submitted:
            raise Exception('Proposal has already been submitted')

        if not self.wallet.network:
            raise Exception('Not connected')

        confirmations, _ = self.wallet.get_confirmations(proposal.fee_txid)
        if confirmations < BUDGET_FEE_CONFIRMATIONS:
            raise Exception('Collateral requires at least %d confirmations' % BUDGET_FEE_CONFIRMATIONS)

        payments_count = proposal.get_payments_count()
        payment_amount = format_satoshis_plain(proposal.payment_amount)
        params = [proposal.proposal_name, proposal.proposal_url, payments_count, proposal.start_block, proposal.address, payment_amount, proposal.fee_txid]

        errmsg = []
        callback = lambda r: self.submit_proposal_callback(proposal.proposal_name, errmsg, r, save)
        self.network_event.clear()
        self.wallet.network.send([('masternode.budget.submit', params)], callback)
        self.network_event.wait()
        if errmsg:
            errmsg = errmsg[0]
        return (errmsg, proposal.submitted)

    def submit_proposal_callback(self, proposal_name, errmsg, r, save = True):
        """Callback for when a proposal has been submitted."""
        try:
            self.on_proposal_submitted(proposal_name, r)
        except Exception as e:
            errmsg.append(str(e))
        finally:
            if save:
                self.save()
            self.network_event.set()

    def on_proposal_submitted(self, proposal_name, r):
        """Validate the server response."""
        proposal = self.get_proposal(proposal_name)
        err = r.get('error')
        if err:
            proposal.rejected = True
            raise Exception('Error response: %s' % str(err))

        result = r.get('result')

        if proposal.get_hash() != result:
            raise Exception('Invalid proposal hash from server: %s' % result)

        proposal.submitted = True

    def retrieve_proposal_hash(self, proposal_name):
        """Retrieve proposal hash from the network."""
        if self.proposal_hash_cache.get(proposal_name):
            return self.proposal_hash_cache[proposal_name]
        req = ('masternode.budget.getproposalhash', [proposal_name])
        proposal_hash = self.wallet.network.synchronous_get([req])[0]
        self.proposal_hash_cache[proposal_name] = proposal_hash
        # Prune the cache.
        while len(self.proposal_hash_cache) > 100:
            self.proposal_hash_cache.popitem(last=False)
        return proposal_hash

    def retrieve_proposal(self, proposal_name):
        """Retrieve proposal information from the network."""
        proposal_hash = self.retrieve_proposal_hash(proposal_name)

        req = ('masternode.budget.getproposal', [proposal_hash])
        result = self.wallet.network.synchronous_get([req])[0]

        kwargs = {'proposal_name': result['Name'], 'proposal_url': result['URL'],
                'start_block': int(result['BlockStart']), 'end_block': int(result['BlockEnd']),
                'payment_amount': int(result['MonthlyPayment']), 'address': result['PaymentAddress'],
                'fee_txid': result['FeeTXHash']}
        return BudgetProposal(**kwargs)

    def retrieve_proposals(self):
        """Retrieve proposals from the network."""
        proposals = []
        def on_list_proposals(proposals, r):
            r = r['result']
            try:
                for k, result in r.items():
                    kwargs = {'proposal_name': result['Name'], 'proposal_url': result['URL'],
                            'start_block': int(result['BlockStart']), 'end_block': int(result['BlockEnd']),
                            'payment_amount': int(result['MonthlyPayment']), 'address': result['PaymentAddress'],
                            'fee_txid': result['FeeTXHash']}
                    proposals.append(BudgetProposal(**kwargs))
            finally:
                self.network_event.set()

        callback = lambda r: on_list_proposals(proposals, r)
        self.network_event.clear()
        self.wallet.network.send([('masternode.budget.list', [])], callback)
        self.network_event.wait()
        return proposals

    def proposals_subscription_response(self, response):
        """Callback for when proposals on the network change."""
        proposals = []
        r = response['result']

        for k, result in r.items():
            kwargs = {'proposal_name': result['Name'], 'proposal_url': result['URL'],
                    'start_block': int(result['BlockStart']), 'end_block': int(result['BlockEnd']),
                    'payment_amount': int(result['MonthlyPayment']), 'address': result['PaymentAddress'],
                    'fee_txid': result['FeeTXHash'],
                    'yes_count': result['YesCount'], 'no_count': result['NoCount']}
            proposals.append(BudgetProposal(**kwargs))

        print_error('Received updated budget proposal information (%d proposals)' % len(proposals))
        self.all_proposals = proposals
        self.wallet.network.trigger_callback('proposals')

    def masternode_subscription_response(self, response):
        """Callback for when a masternode's status changes."""
        collateral = response['params'][0]
        mn = None
        for masternode in self.masternodes:
            if masternode.get_collateral_str() == collateral:
                mn = masternode
                break

        if not mn:
            return

        status = response['result']
        if status is None:
            status = False
        print_error('Received updated status for masternode %s: "%s"' % (mn.alias, status))
        self.masternode_statuses[collateral] = status
