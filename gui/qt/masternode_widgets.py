"""Masternode-related widgets."""

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum_dash import bitcoin
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
        self.vin = {}
        self.hash_edit = QLineEdit()
        self.hash_edit.setPlaceholderText(_('The TxID of your 1000 DASH output'))
        self.index_edit = QLineEdit()
        self.index_edit.setPlaceholderText(_('The output number of your 1000 DASH output'))
        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText(_('The address that 1000 DASH was sent to'))

        # Collection of fields so that it's easier to act on them all at once.
        self.fields = (self.hash_edit, self.index_edit, self.address_edit)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.addRow(_('TxID:'), self.hash_edit)
        form.addRow(_('Output Index:'), self.index_edit)
        form.addRow(_('Address:'), self.address_edit)
        self.setLayout(form)

    @pyqtProperty(str)
    def string(self):
        return self.get_str()

    @string.setter
    def string(self, value):
        return self.set_str(str(value))

    def get_str(self):
        values = [str(self.hash_edit.text()), str(self.index_edit.text()), str(self.address_edit.text())]
        values.append(str(self.vin.get('value', '')))
        values.append(self.vin.get('scriptSig', ''))
        return ':'.join(values)

    def set_str(self, value):
        s = str(value).split(':')
        values = []
        try:
            values.append(('prevout_hash', s[0]))
            values.append(('prevout_n', int(s[1])))
            values.append(('address', s[2]))
            values.append(('value', int(s[3])))
            values.append(('scriptSig', s[4]))
        # Don't fail if not all values are present.
        except (IndexError, ValueError):
            pass

        vin = {k: v for k, v in values}
        self.hash_edit.setText(vin.get('prevout_hash', ''))
        self.index_edit.setText(str(vin.get('prevout_n', '')))
        self.address_edit.setText(vin.get('address', ''))

        self.vin = vin

    def get_dict(self):
        d = {}
        txid = str(self.hash_edit.text())
        if not txid:
            return d
        index = str(self.index_edit.text())
        if not index:
            index = '0'
        address = str(self.address_edit.text())
        d['prevout_hash'] = txid
        d['prevout_n'] = int(index)
        d['address'] = address
        if self.vin:
            d['value'] = int(self.vin.get('value', '0'))
            d['scriptSig'] = self.vin.get('scriptSig', '')
        return d

    def set_dict(self, d):
        self.hash_edit.setText(d.get('prevout_hash', ''))
        self.index_edit.setText(str(d.get('prevout_n', '')))
        self.address_edit.setText(d.get('address', ''))
        self.vin = dict(d)

    def clear(self):
        for widget in self.fields:
            widget.clear()
        self.vin = {}

    def setReadOnly(self, isreadonly):
        for widget in self.fields:
            widget.setReadOnly(isreadonly)

class MasternodeEditor(QWidget):
    """Editor for masternodes."""
    def __init__(self, parent=None):
        super(MasternodeEditor, self).__init__(parent)

        self.alias_edit = QLineEdit()
        self.alias_edit.setPlaceholderText(_('Enter a name for this masternode'))

        self.vin_edit = PrevOutWidget()

        self.addr_edit = NetworkAddressWidget()
        self.delegate_key_edit = QLineEdit()
        self.delegate_key_edit.setPlaceholderText(_('The address that your masternode will sign messages with'))
        self.protocol_version_edit = QLineEdit()
        self.protocol_version_edit.setText('70103')

        self.announced_checkbox = util.ReadOnlyCheckBox(_('Activated'))


        form = QFormLayout()
        form.addRow(_('Alias:'), self.alias_edit)

        form.addRow(_('Collateral DASH Output:'), self.vin_edit)

        form.addRow(_('Address:'), self.addr_edit)
        form.addRow(_('Masternode DASH Address:'), self.delegate_key_edit)
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
        protocol_version = str(self.protocol_version_edit.text())
        if protocol_version:
            kwargs['protocol_version'] = int(protocol_version)
        # Don't pass whether announced_checkbox is checked, because a new
        # masternode can't be announced already.

        return kwargs

class MasternodeOutputsWidget(QListWidget):
    """Widget that displays available masternode outputs."""
    outputSelected = pyqtSignal(dict, name='outputSelected')
    def __init__(self, parent=None):
        super(MasternodeOutputsWidget, self).__init__(parent)
        self.outputs = {}
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.selectionModel().selectionChanged.connect(self.on_selection_changed)

    def sizeHint(self):
        return QSize(256, 60)

    def add_output(self, d):
        """Add a valid output."""
        label = '%s:%s' % (d['prevout_hash'], d['prevout_n'])
        self.outputs[label] = d
        self.addItem(label)

    def add_outputs(self, outputs):
        map(self.add_output, outputs)
        self.setCurrentRow(0)

    def clear(self):
        super(MasternodeOutputsWidget, self).clear()
        self.outputs.clear()

    def on_selection_changed(self, selected, deselected):
        """Emit the selected output."""
        items = self.selectedItems()
        if not items:
            return
        self.outputSelected.emit(self.outputs[str(items[0].text())])

class SignAnnounceWidget(QWidget):
    """Widget that displays information about signing a Masternode Announce."""
    def __init__(self, parent):
        super(SignAnnounceWidget, self).__init__(parent)
        self.dialog = parent
        self.manager = parent.manager

        include_frozen_checkbox = QCheckBox(_('Include frozen addresses'))
        include_frozen_checkbox.setChecked(False)
        self.scan_outputs_button = QPushButton(_('Scan For Masternode Outputs'))
        def on_scan_outputs():
            """Call scan_for_outputs() with whether to include frozen addresses."""
            self.scan_for_outputs(include_frozen_checkbox.isChecked())
        self.scan_outputs_button.clicked.connect(on_scan_outputs)

        self.valid_outputs_list = MasternodeOutputsWidget()
        self.valid_outputs_list.outputSelected.connect(self.set_output)

        self.alias_edit = QLineEdit()
        self.collateral_edit = PrevOutWidget()
        self.delegate_edit = QLineEdit()

        for i in [self.alias_edit, self.collateral_edit, self.delegate_edit]:
            i.setReadOnly(True)

        self.mapper = QDataWidgetMapper()
        self.mapper.setSubmitPolicy(QDataWidgetMapper.ManualSubmit)
        self.mapper.setModel(self.dialog.masternodes_widget.proxy_model)

        model = self.dialog.masternodes_widget.model
        self.mapper.addMapping(self.alias_edit, model.ALIAS)
        self.mapper.addMapping(self.collateral_edit, model.VIN, 'string')
        self.mapper.addMapping(self.delegate_edit, model.DELEGATE)

        self.sign_button = QPushButton(_('Activate Masternode'))
        self.sign_button.setEnabled(False)
        self.sign_button.clicked.connect(self.sign_announce)

        valid_outputs_box = QVBoxLayout()
        valid_outputs_box.addWidget(QLabel(_('Masternode Outputs:')))
        valid_outputs_box.addWidget(self.valid_outputs_list)

        form = QFormLayout()
        form.addRow(util.Buttons(include_frozen_checkbox, self.scan_outputs_button))
        form.addRow(valid_outputs_box)
        form.addRow(_('Alias:'), self.alias_edit)
        form.addRow(_('1000 DASH Output:'), self.collateral_edit)
        form.addRow(_('Masternode DASH Address:'), self.delegate_edit)
        form.addRow(util.Buttons(self.sign_button))
        self.setLayout(form)

    def set_mapper_index(self, row):
        self.valid_outputs_list.clear()
        self.mapper.setCurrentIndex(row)
        mn = self.dialog.masternodes_widget.masternode_for_row(row)
        can_scan, can_sign = True, True
        # Disable both buttons if the masternode has already been activated.
        if mn.announced:
            can_scan, can_sign = False, False
        # Disable the scan_outputs button if the masternode already has an assigned output.
        elif mn.vin.get('value', 0) == COIN * 1000:
            can_scan = False
            self.valid_outputs_list.add_output(mn.vin)

        self.scan_outputs_button.setEnabled(can_scan)
        self.sign_button.setEnabled(can_sign)

    def set_output(self, vin):
        """Set the masternode's output to the selected one."""
        self.collateral_edit.set_dict(vin)

    def scan_for_outputs(self, include_frozen):
        """Scan for 1000 DASH outputs.

        If one or more is found, populate the list and enable the sign button.
        """
        self.valid_outputs_list.clear()
        exclude_frozen = not include_frozen

        coins = self.manager.get_masternode_outputs(exclude_frozen=exclude_frozen)

        if len(coins) > 0:
            self.valid_outputs_list.add_outputs(coins)
            self.sign_button.setEnabled(True)
        else:
            self.collateral_edit.set_str(_('There are no 1000 DASH outputs in your wallet.:'))

    def sign_announce(self):
        """Set the masternode's vin and sign an announcement."""
        self.mapper.submit()
        self.dialog.sign_announce(str(self.alias_edit.text()))

