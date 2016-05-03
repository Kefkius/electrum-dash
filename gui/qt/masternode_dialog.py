from base64 import b64encode
from datetime import datetime
import os

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum_dash import bitcoin
from electrum_dash.i18n import _
from electrum_dash.masternode import MasternodeAnnounce
from electrum_dash.masternode_manager import parse_masternode_conf
from electrum_dash.util import print_error

from masternode_widgets import *
import util


class MasternodesModel(QAbstractTableModel):
    """Model for masternodes."""
    ALIAS = 0
    VIN = 1
    ADDR = 2
    COLLATERAL = 3
    DELEGATE = 4
    PROTOCOL_VERSION = 5
    ANNOUNCED = 6
    TOTAL_FIELDS = 7


    def __init__(self, manager, parent=None):
        super(MasternodesModel, self).__init__(parent)
        self.manager = manager
        self.masternodes = self.manager.masternodes

        headers = [
            {Qt.DisplayRole: 'Alias',},
            {Qt.DisplayRole: 'Collateral',},
            {Qt.DisplayRole: 'Address',},
            {Qt.DisplayRole: 'Collateral Key',},
            {Qt.DisplayRole: 'Delegate Key',},
            {Qt.DisplayRole: 'Protocol Version',},
            {Qt.DisplayRole: 'Activated',},
        ]
        for d in headers:
            d[Qt.EditRole] = d[Qt.DisplayRole]
        self.headers = headers

    def add_masternode(self, masternode, save = True):
        self.beginResetModel()
        self.manager.add_masternode(masternode, save)
        self.endResetModel()

    def remove_masternode(self, alias, save = True):
        self.beginResetModel()
        self.manager.remove_masternode(alias, save)
        self.endResetModel()

    def masternode_for_row(self, row):
        mn = self.masternodes[row]
        return mn

    def columnCount(self, parent=QModelIndex()):
        return self.TOTAL_FIELDS

    def rowCount(self, parent=QModelIndex()):
        return len(self.masternodes)

    def headerData(self, section, orientation, role = Qt.DisplayRole):
        if role not in [Qt.DisplayRole, Qt.EditRole]: return None
        if orientation != Qt.Horizontal: return None

        data = None
        try:
            data = self.headers[section][role]
        except (IndexError, KeyError):
            pass

        return QVariant(data)

    def data(self, index, role = Qt.DisplayRole):
        data = None
        if not index.isValid():
            return QVariant(data)
        if role not in [Qt.DisplayRole, Qt.EditRole, Qt.CheckStateRole, Qt.ToolTipRole]:
            return None

        mn = self.masternodes[index.row()]
        i = index.column()

        # Only the Activated column has a checkbox.
        if role == Qt.CheckStateRole and i != self.ANNOUNCED:
            return None

        if i == self.ALIAS:
            data = mn.alias
        elif i == self.VIN:
            txid = mn.vin.get('prevout_hash')
            out_n = mn.vin.get('prevout_n')
            addr = mn.vin.get('address')
            if txid is not None and out_n is not None and addr is not None:
                data = '%s:%d-%s' % (txid, out_n, addr)
            else:
                data = ''
        elif i == self.ADDR:
            data = ''
            if mn.addr.ip:
                data = str(mn.addr)
        elif i == self.COLLATERAL:
            data = mn.collateral_key
            if role in [Qt.EditRole, Qt.DisplayRole, Qt.ToolTipRole] and data:
                data = bitcoin.public_key_to_bc_address(data.decode('hex'))
        elif i == self.DELEGATE:
            data = mn.delegate_key
            if role in [Qt.EditRole, Qt.DisplayRole, Qt.ToolTipRole] and data:
                data = bitcoin.public_key_to_bc_address(data.decode('hex'))
        elif i == self.PROTOCOL_VERSION:
            data = mn.protocol_version
        elif i == self.ANNOUNCED:
            data = mn.announced
            if role == Qt.CheckStateRole:
                data = Qt.Checked if data else Qt.Unchecked
            elif role == Qt.DisplayRole:
                data = _('Yes') if data else _('No')

        return QVariant(data)

    def setData(self, index, value, role = Qt.EditRole):
        if not index.isValid(): return False

        mn = self.masternodes[index.row()]
        i = index.column()

        if i == self.ALIAS:
            mn.alias = str(value.toString())
        elif i == self.VIN:
            return False
        elif i == self.ADDR:
            s = str(value.toString()).split(':')
            mn.addr.ip = s[0]
            mn.addr.port = int(s[1])
        elif i == self.COLLATERAL:
            return False
        elif i == self.DELEGATE:
            address = str(value.toString())
            pubkey = self.manager.wallet.get_public_keys(address)[0]
            mn.delegate_key = pubkey
        elif i == self.PROTOCOL_VERSION:
            version, ok = value.toInt()
            if not ok:
                return False
            mn.protocol_version = version
        elif i == self.ANNOUNCED:
            mn.announced = value.toBool()
        else:
            return False

        self.dataChanged.emit(self.index(index.row(), index.column()), self.index(index.row(), index.column()))
        return True

class MasternodesWidget(QWidget):
    """Widget that displays masternodes."""
    def __init__(self, manager, parent=None):
        super(MasternodesWidget, self).__init__(parent)
        self.manager = manager
        self.model = MasternodesModel(self.manager)
        self.view = QTableView()
        self.view.setModel(self.model)
        for header in [self.view.horizontalHeader(), self.view.verticalHeader()]:
            header.setHighlightSections(False)

        header = self.view.horizontalHeader()
        header.setResizeMode(MasternodesModel.ALIAS, QHeaderView.Interactive)
        header.setResizeMode(MasternodesModel.VIN, QHeaderView.Stretch)
        header.setResizeMode(MasternodesModel.COLLATERAL, QHeaderView.ResizeToContents)
        header.setResizeMode(MasternodesModel.DELEGATE, QHeaderView.ResizeToContents)
        header.setResizeMode(MasternodesModel.PROTOCOL_VERSION, QHeaderView.ResizeToContents)

        self.view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self.view)
        self.setLayout(vbox)

    def add_masternode(self, masternode, save = True):
        self.model.add_masternode(masternode, save=save)

    def remove_masternode(self, alias, save = True):
        self.model.remove_masternode(alias, save=save)

class MasternodeDialog(QDialog):
    """GUI for managing masternodes."""

    def __init__(self, manager, parent):
        super(MasternodeDialog, self).__init__(parent)
        self.gui = parent
        self.manager = manager
        self.setWindowTitle(_('Masternode Manager'))

        self.waiting_dialog = None
        self.create_layout()
        # Create a default masternode if none are present.
        if len(self.manager.masternodes) == 0:
            self.masternodes_widget.add_masternode(MasternodeAnnounce(alias='default'), save=False)
        self.masternodes_widget.view.selectRow(0)

    def sizeHint(self):
        return QSize(770, 600)

    def create_layout(self):
        self.masternodes_widget = MasternodesWidget(self.manager)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_view_masternode_tab(), _('View Masternode'))
        self.tabs.addTab(self.create_sign_announce_tab(), _('Activate Masternode'))
        self.tabs.addTab(self.create_masternode_conf_tab(), _('Masternode.conf'))

        # Connect to the selection signal so we can update the widget mapper.
        self.masternodes_widget.view.selectionModel().selectionChanged.connect(self.on_view_selection_changed)

        bottom_buttons = util.Buttons(util.CloseButton(self))

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Masternodes:')))
        vbox.addWidget(self.masternodes_widget, stretch=1)
        vbox.addWidget(self.tabs)
        vbox.addLayout(bottom_buttons)
        self.setLayout(vbox)

    def create_view_masternode_tab(self):
        """Create the tab used to view masternodes."""
        collateral_desc = QLabel(_(''.join(['The "Collateral DASH Output" field below will appear blank until ',
                'you activate this masternode.'])))
        collateral_desc.setWordWrap(True)

        self.masternode_editor = editor = MasternodeEditor()
        model = self.masternodes_widget.model
        self.mapper = mapper = QDataWidgetMapper()

        editor.alias_edit.textChanged.connect(self.on_editor_alias_changed)

        mapper.setSubmitPolicy(QDataWidgetMapper.ManualSubmit)
        mapper.setModel(model)
        mapper.addMapping(editor.alias_edit, model.ALIAS)

        editor.vin_edit.setReadOnly(True)
        mapper.addMapping(editor.vin_edit, model.VIN, 'string')

        mapper.addMapping(editor.addr_edit, model.ADDR, 'string')
        mapper.addMapping(editor.delegate_key_edit, model.DELEGATE)
        mapper.addMapping(editor.protocol_version_edit, model.PROTOCOL_VERSION)

        mapper.addMapping(editor.announced_checkbox, model.ANNOUNCED)

        self.save_new_masternode_button = QPushButton('Save As New Masternode')
        self.save_new_masternode_button.clicked.connect(lambda: self.save_current_masternode(as_new=True))

        self.save_masternode_button = QPushButton(_('Save Masternode'))
        self.save_masternode_button.clicked.connect(self.save_current_masternode)

        self.delete_masternode_button = QPushButton(_('Delete Masternode'))
        self.delete_masternode_button.clicked.connect(self.delete_current_masternode)

        vbox = QVBoxLayout()
        vbox.addWidget(collateral_desc)
        vbox.addWidget(editor)
        vbox.addLayout(util.Buttons(self.delete_masternode_button,
                self.save_new_masternode_button, self.save_masternode_button))
        w = QWidget()
        w.setLayout(vbox)
        return w

    def create_masternode_conf_tab(self):
        """Create the tab used to import masternode.conf files."""

        desc = ' '.join(['You can use this form to import your masternode.conf file.',
            'This file is usually located in the same directory that your wallet file is in.',
            'If you just need to import your masternode\'s private key, use the regular process for importing a key.'])
        desc = QLabel(_(desc))
        desc.setWordWrap(True)

        import_filename_edit = QLineEdit()
        import_filename_edit.setPlaceholderText(_('Enter the path to your masternode.conf'))
        import_select_file = QPushButton(_('Select File...'))
        hbox = QHBoxLayout()
        hbox.addWidget(import_filename_edit, stretch=1)
        hbox.addWidget(import_select_file)
        import_conf_button = QPushButton(_('Import'))
        vbox = QVBoxLayout()
        vbox.addWidget(desc)
        vbox.addLayout(hbox)
        vbox.addLayout(util.Buttons(import_conf_button))
        vbox.addStretch(1)

        def select_import_file():
            text = QFileDialog.getOpenFileName(None, _('Select a file to import'), '', '*.conf')
            if text:
                import_filename_edit.setText(text)
        import_select_file.clicked.connect(select_import_file)

        def do_import_file():
            path = str(import_filename_edit.text())
            self.import_masternode_conf(path)
        import_conf_button.clicked.connect(do_import_file)

        w = QWidget()
        w.setLayout(vbox)
        return w

    def import_masternode_conf(self, filename):
        """Import a masternode.conf file."""
        pw = None
        if self.manager.wallet.use_encryption:
            pw = self.gui.password_dialog(msg=_('Please enter your password to import Masternode information.'))
            if pw is None:
                return

        if not os.path.exists(filename):
            QMessageBox.critical(self, _('Error'), _('File does not exist'))
            return
        with open(filename, 'r') as f:
            lines = f.readlines()

        try:
            conf_lines = parse_masternode_conf(lines)
        except Exception as e:
            QMessageBox.critical(self, _('Error'), _(str(e)))
        else:
            self.manager.import_masternode_conf_lines(conf_lines, pw)

    def selected_masternode(self):
        """Get the currently-selected masternode."""
        row = self.mapper.currentIndex()
        mn = self.masternodes_widget.model.masternode_for_row(row)
        return mn

    def delete_current_masternode(self):
        """Delete the masternode that is being viewed."""
        mn = self.selected_masternode()
        self.masternodes_widget.model.remove_masternode(mn.alias)

    def save_current_masternode(self, as_new=False):
        """Save the masternode that is being viewed.

        If as_new is True, a new masternode will be created.
        """
        # Make sure that we have the key for the delegate address.
        delegate_addr = str(self.masternode_editor.delegate_key_edit.text())
        try:
            _pub = self.manager.wallet.get_public_keys(delegate_addr)
        except Exception as e:
            QMessageBox.critical(self, _('Error'), _(str(e)))
            return

        # Construct a new masternode.
        if as_new:
            kwargs = self.masternode_editor.get_masternode_args()
            collateral_address = self.manager.wallet.get_public_keys(kwargs['vin']['address'])[0]
            kwargs['collateral_key'] = collateral_address
            del kwargs['vin']
            self.mapper.revert()
            self.masternodes_widget.add_masternode(MasternodeAnnounce(**kwargs))
            self.mapper.toLast()
        else:
            self.mapper.submit()
        self.manager.save()

    def on_view_selection_changed(self, selected, deselected):
        """Update the data widget mapper."""
        try:
            idx = selected.indexes()[0]
            self.mapper.setCurrentIndex(idx.row())
            self.sign_announce_widget.set_masternode(self.selected_masternode())
        except Exception:
            self.mapper.setCurrentIndex(0)

    def on_editor_alias_changed(self, text):
        """Enable or disable the 'Save As New Masternode' button.

        Aliases must be unique and have at least one character.
        """
        text = str(text)
        # Check if the alias already exists.
        enable = len(text) > 0 and self.manager.get_masternode(text) is None
        self.save_new_masternode_button.setEnabled(enable)

    def create_sign_announce_tab(self):
        desc = ' '.join(['You can sign a Masternode Announce message to activate your masternode.',
            'First, scan for valid 1000 DASH outputs below.',
            'Then, click "Activate Masternode" to activate your masternode.',
        ])
        desc = QLabel(_(desc))
        desc.setWordWrap(True)

        self.sign_announce_widget = SignAnnounceWidget(self)

        vbox = QVBoxLayout()
        vbox.addWidget(desc)
        vbox.addWidget(self.sign_announce_widget)
        vbox.addStretch(1)

        w = QWidget()
        w.setLayout(vbox)
        return w

    def sign_announce(self, alias):
        """Sign an announce for alias. This is called by SignAnnounceWidget."""
        pw = None
        if self.manager.wallet.use_encryption:
            pw = self.gui.password_dialog(msg=_('Please enter your password to activate masternode "%s".' % alias))
            if pw is None:
                return

        self.sign_announce_widget.sign_button.setEnabled(False)
        success = [False]

        def sign_thread():
            return self.manager.sign_announce(alias, pw)

        def on_sign_successful(mn):
            success[0] = True
        # Proceed to broadcasting the announcement, or re-enable the button.
        def on_waiting_done():
            if success[0]:
                self.send_announce(alias)
            else:
                self.sign_announce_widget.sign_button.setEnabled(True)


        self.waiting_dialog = util.WaitingDialog(self, _('Signing Masternode Announce...'), sign_thread, on_sign_successful, on_waiting_done)
        self.waiting_dialog.start()


    def send_announce(self, alias):
        """Send an announce for a masternode."""
        def send_thread():
            return self.manager.send_announce(alias)

        def on_send_successful(errmsg, was_announced):
            if was_announced:
                QMessageBox.information(self, _('Success'), _('Masternode "%s" activated successfully.' % alias))
                print_error('Successfully broadcasted MasternodeAnnounce for "%s"' % alias)
            else:
                QMessageBox.critical(self, _('Error Sending'), _(errmsg))
                print_error('Failed to broadcast MasternodeAnnounce')

        def on_waiting_done():
            self.sign_announce_widget.set_masternode(self.manager.get_masternode(alias))
            self.masternodes_widget.model.dataChanged.emit(QModelIndex(), QModelIndex())

        self.waiting_dialog = util.WaitingDialog(self, _('Broadcasting masternode...'), send_thread, on_send_successful, on_waiting_done)
        self.waiting_dialog.start()
