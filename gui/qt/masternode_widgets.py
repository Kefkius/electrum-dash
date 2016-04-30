"""Masternode-related widgets."""

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum_dash.bitcoin import COIN
from electrum_dash.i18n import _
from electrum_dash.masternode import NetworkAddress, MasternodeAnnounce

import util

class NetworkAddressWidget(QWidget):
    """Widget that represents a network address."""
    def __init__(self, parent=None):
        super(NetworkAddressWidget, self).__init__(parent)
        self.ip_edit = QLineEdit()
        self.port_edit = QSpinBox()
        self.port_edit.setRange(0, 99999)

        hbox = QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.addWidget(QLabel(_('IP:')))
        hbox.addWidget(self.ip_edit, stretch=1)
        hbox.addWidget(QLabel(_('Port:')))
        hbox.addWidget(self.port_edit, stretch=1)
        self.setLayout(hbox)

    @pyqtProperty(str)
    def string(self):
        return '%s:%d' % (str(self.ip_edit.text()), self.port_edit.value())

    @string.setter
    def string(self, value):
        s = str(value).split(':')
        ip = ''
        port = 0
        if len(s) > 0:
            ip = s[0]
        if len(s) > 1:
            port = int(s[1])
        self.ip_edit.setText(ip)
        self.port_edit.setValue(port)

    def get_addr(self):
        """Get a NetworkAddress instance from this widget's data."""
        ip = str(self.ip_edit.text())
        port = self.port_edit.value()
        if self.validate_ip(ip):
            return NetworkAddress(ip=ip, port=port)

    # TODO IPv6 support.
    def validate_ip(self, s):
        try:
            ip = s.split('.')
            if len(ip) != 4:
                raise Exception('Invalid length')
            for i in ip:
                if int(i) < 0 or int(i) > 255:
                    raise ValueError('Invalid IP byte')
        except Exception:
            return False
        return True


class PrevOutWidget(QWidget):
    """Widget that represents a previous outpoint."""
    def __init__(self, parent=None):
        super(PrevOutWidget, self).__init__(parent)
        self.hash_edit = QLineEdit()
        self.hash_edit.setPlaceholderText(_('The TxID of your 1000 DASH output'))
        self.index_edit = QLineEdit()
        self.index_edit.setPlaceholderText(_('The output number of your 1000 DASH output'))

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.addRow(_('TxID:'), self.hash_edit)
        form.addRow(_('Output Index:'), self.index_edit)
        self.setLayout(form)

    @pyqtProperty(str)
    def string(self):
        return self.get_str()

    @string.setter
    def string(self, value):
        return self.set_str(str(value))

    def get_str(self):
        return '%s:%s' % (str(self.hash_edit.text()), self.index_edit.text())

    def set_str(self, value):
        s = str(value).split(':')
        hash = ''
        index = ''
        if len(s) > 0:
            hash = s[0]
        if len(s) > 1:
            index = s[1]
        self.hash_edit.setText(hash)
        self.index_edit.setText(index)

    def get_dict(self):
        d = {}
        txid = str(self.hash_edit.text())
        if not txid:
            return d
        index = str(self.index_edit.text())
        if not index:
            index = '0'
        d['prevout_hash'] = txid
        d['prevout_n'] = int(index)
        return d

    def set_dict(self, d):
        self.hash_edit.setText(d.get('prevout_hash', ''))
        self.index_edit.setText(str(d.get('prevout_n', '0')))

    def clear(self):
        self.hash_edit.clear()
        self.index_edit.clear()

    def setReadOnly(self, isreadonly):
        self.hash_edit.setReadOnly(isreadonly)
        self.index_edit.setReadOnly(isreadonly)

class MasternodeEditor(QWidget):
    """Editor for masternodes."""
    def __init__(self, parent=None):
        super(MasternodeEditor, self).__init__(parent)

        self.alias_edit = QLineEdit()
        self.alias_edit.setPlaceholderText(_('Enter a name for this masternode'))

        self.vin_edit = PrevOutWidget()

        self.addr_edit = NetworkAddressWidget()
        self.collateral_key_edit = QLineEdit()
        self.collateral_key_edit.setPlaceholderText(_('Enter the public key of your 1000 DASH key'))
        self.delegate_key_edit = QLineEdit()
        self.delegate_key_edit.setPlaceholderText(_('Enter the public key of your masternode'))
        self.protocol_version_edit = QLineEdit()
        self.protocol_version_edit.setText('70103')

        self.announced_checkbox = util.ReadOnlyCheckBox(_('Activated'))


        form = QFormLayout()
        form.addRow(_('Alias:'), self.alias_edit)

        form.addRow(_('Collateral DASH Output:'), self.vin_edit)

        form.addRow(_('Address:'), self.addr_edit)
        form.addRow(_('Collateral Key:'), self.collateral_key_edit)
        form.addRow(_('Delegate Key:'), self.delegate_key_edit)
        form.addRow(_('Protocol Version:'), self.protocol_version_edit)
        form.addRow(self.announced_checkbox)


        self.setLayout(form)

    def get_masternode_args(self):
        """Get MasternodeAnnounce keyword args from this widget's data."""
        kwargs = {}
        kwargs['alias'] = str(self.alias_edit.text())

        vin = self.vin_edit.get_dict()
        kwargs['vin'] = vin

        kwargs['addr'] = self.addr_edit.get_addr()
        kwargs['collateral_key'] = str(self.collateral_key_edit.text())
        kwargs['delegate_key'] = str(self.delegate_key_edit.text())
        protocol_version = str(self.protocol_version_edit.text())
        if protocol_version:
            kwargs['protocol_version'] = int(protocol_version)
        # Don't pass whether announced_checkbox is checked, because a new
        # masternode can't be announced already.

        return kwargs

class SignAnnounceWidget(QWidget):
    """Widget that displays information about signing a Masternode Announce."""
    def __init__(self, parent):
        super(SignAnnounceWidget, self).__init__(parent)
        self.dialog = parent
        self.manager = parent.manager
        # The 1000 Dash vin.
        self.vin = None

        include_frozen_checkbox = QCheckBox(_('Include frozen addresses'))
        include_frozen_checkbox.setChecked(False)
        self.scan_outputs_button = QPushButton(_('Scan For Masternode Outputs'))
        def on_scan_outputs():
            """Call scan_for_outputs() with whether to include frozen addresses."""
            self.scan_for_outputs(include_frozen_checkbox.isChecked())
        self.scan_outputs_button.clicked.connect(on_scan_outputs)

        self.alias_edit = QLineEdit()
        self.collateral_edit = PrevOutWidget()

        self.sign_button = QPushButton(_('Activate Masternode'))
        self.sign_button.setEnabled(False)
        self.sign_button.clicked.connect(self.sign_announce)

        for i in [self.alias_edit, self.collateral_edit]:
            i.setReadOnly(True)

        form = QFormLayout()
        form.addRow(util.Buttons(include_frozen_checkbox, self.scan_outputs_button))
        form.addRow(_('Alias:'), self.alias_edit)
        form.addRow(_('1000 DASH Output:'), self.collateral_edit)
        form.addRow(util.Buttons(self.sign_button))
        self.setLayout(form)

    def set_masternode(self, mn):
        # Disable if the masternode was already activated.
        self.setEnabled(True)
        if mn.announced:
            self.setEnabled(False)
            return
        self.alias_edit.setText(mn.alias)
        self.clear_fields()
        # Fill in the collateral if the masternode already has it.
        if mn.vin.get('value', 0) == COIN * 1000:
            self.collateral_edit.set_dict(mn.vin)
            self.vin = mn.vin
            self.scan_outputs_button.setEnabled(False)
            self.sign_button.setEnabled(True)

    def scan_for_outputs(self, include_frozen):
        """Scan for 1000 DASH outputs.

        If one is found, set self.vin and enable the sign button.
        """
        self.clear_fields()
        exclude_frozen = not include_frozen

        coins = self.manager.get_masternode_outputs(exclude_frozen=exclude_frozen)

        if len(coins) > 0:
            self.vin = coins[0]
            self.collateral_edit.set_str('%s:%s'%(self.vin['prevout_hash'], self.vin['prevout_n']))
            self.sign_button.setEnabled(True)
        else:
            self.collateral_edit.set_str(_('There are no 1000 DASH outputs in your wallet.:'))

    def sign_announce(self):
        """Set the masternode's vin and sign an announcement."""
        mn = self.manager.get_masternode(str(self.alias_edit.text()))
        mn.vin = self.vin
        self.dialog.sign_announce(mn.alias)

    def clear_fields(self):
        self.vin = None
        self.collateral_edit.clear()
        self.scan_outputs_button.setEnabled(True)
        self.sign_button.setEnabled(False)
