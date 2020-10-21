#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from electroncash.i18n import _, ngettext
import electroncash.web as web
from electroncash.address import Address
from electroncash.contacts import Contact, contact_types
from electroncash.plugins import run_hook
from electroncash.util import FileImportFailed, PrintError, finalization_print_error
# TODO: whittle down these * imports to what we actually use when done with
# our changes to this class -Calin
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from .util import (MyTreeWidget, webopen, WindowModalDialog, Buttons,
                   CancelButton, OkButton, HelpLabel, WWLabel,
                   destroyed_print_error, webopen, ColorScheme, MONOSPACE_FONT,
                   rate_limited)
from enum import IntEnum
from collections import defaultdict
from typing import List, Set, Dict, Tuple
#from . import cashacctqt

class ContactList(PrintError, MyTreeWidget):
    filter_columns = [1, 2, 3]  # Name, Label, Address
    default_sort = MyTreeWidget.SortSpec(1, Qt.AscendingOrder)

    do_update_signal = pyqtSignal()
    _ca_minimal_chash_updated_signal = pyqtSignal(object, str)

    class DataRoles(IntEnum):
        Contact     = Qt.UserRole + 0

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu,
                              ["", _('Name'), _('Label'), _('Address'), _('Type') ], 2, [1,2],  # headers, stretch_column, editable_columns
                              deferred_updates=True, save_sort_settings=True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.wallet = parent.wallet
        self.setIndentation(0)
        self._edited_item_cur_sel = (None,) * 3
        self.monospace_font = QFont(MONOSPACE_FONT)
        self.cleaned_up = False
        self.do_update_signal.connect(self.update)
        # self.icon_cashacct = QIcon(":icons/cashacct-logo.png" if not ColorScheme.dark_scheme else ":icons/cashacct-button-darkmode.png")
        # self.icon_openalias = QIcon(":icons/openalias-logo.svg")
        self.icon_contacts = QIcon(":icons/tab_contacts.png")
        self.icon_unverif = QIcon(":/icons/unconfirmed.svg")
        # the below dict is ephemeral and goes away on wallet close --
        # it's populated ultimately by the notify() subsystem in main_window
        #self._ca_pending_conf : Dict[str, Tuple[str, Address]] = dict()  #  "txid" -> ("name", Address)

    def clean_up(self):
        self.cleaned_up = True
        # except TypeError: pass
        try: self.do_update_signal.disconnect(self.update)
        except TypeError: pass
        try: self.parent.gui_object.cashaddr_toggled_signal.disconnect(self.update)
        except TypeError: pass

    def on_permit_edit(self, item, column):
        # openalias items shouldn't be editable
        if column == 2: # Label, always editable
            return True
        return item.data(0, self.DataRoles.Contact).type in ('address', 'cashacct')

    def on_edited(self, item, column, prior_value):
        contact = item.data(0, self.DataRoles.Contact)
        if column == 2: # Label
            label_key = contact.address
            try: label_key = Address.from_string(label_key).to_storage_string()
            except: pass
            self.wallet.set_label(label_key, item.text(2))
            self.update() # force refresh in case 2 contacts use the same address
            return
        # else.. Name
        typ = contact.type
        was_cur, was_sel = bool(self.currentItem()), item.isSelected()
        name, value = item.text(1), item.text(3)
        del item  # paranoia

        # On success, parent.set_contact returns the new key (address text)
        # if 'cashacct'.. or always the same key for all other types.
        key = self.parent.set_contact(name, value, typ=typ, replace=contact)

        if key:
            # Due to deferred updates, on_update will actually be called later.
            # So, we have to save the edited item's "current" and "selected"
            # status here. 'on_update' will look at this tuple and clear it
            # after updating.
            self._edited_item_cur_sel = (key, was_cur, was_sel)

    def import_contacts(self):
        wallet_folder = self.parent.get_wallet_folder()
        filename, __ = QFileDialog.getOpenFileName(self.parent, "Select your wallet file", wallet_folder)
        if not filename:
            return
        try:
            num = self.parent.contacts.import_file(filename)
            self.parent.show_message(_("{} contacts successfully imported.").format(num))
        except Exception as e:
            self.parent.show_error(_("Electron Cash was unable to import your contacts.") + "\n" + repr(e))
        self.on_update()

    def export_contacts(self):
        if self.parent.contacts.empty:
            self.parent.show_error(_("Your contact list is empty."))
            return
        try:
            fileName = self.parent.getSaveFileName(_("Select file to save your contacts"), 'electron-cash-contacts.json', "*.json")
            if fileName:
                num = self.parent.contacts.export_file(fileName)
                self.parent.show_message(_("{} contacts exported to '{}'").format(num, fileName))
        except Exception as e:
            self.parent.show_error(_("Electron Cash was unable to export your contacts.") + "\n" + repr(e))

    def find_item(self, key: Contact) -> QTreeWidgetItem:
        ''' Rather than store the item reference in a lambda, we store its key.
        Storing the item reference can lead to C++ Runtime Errors if the
        underlying QTreeWidgetItem is deleted on .update() while the right-click
        menu is still up. This function returns a currently alive item given a
        key. '''
        for item in self.get_leaves():
            if item.data(0, self.DataRoles.Contact) == key:
                return item

    def _on_edit_item(self, key : Contact, column : int):
        ''' Callback from context menu, private method. '''
        item = self.find_item(key)
        if item:
            self.editItem(item, column)

    @staticmethod
    def _i2c(item : QTreeWidgetItem) -> Contact:
        return item.data(0, ContactList.DataRoles.Contact)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        i2c = self._i2c
        if selected:
            names = [item.text(1) for item in selected]
            keys = [i2c(item) for item in selected]
            payable_keys = [k for k in keys if k.type != 'script']
            deletable_keys = [k for k in keys if k.type in contact_types]
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            item = self.currentItem()
            typ = i2c(item).type if item else 'unknown'
            ca_info = None
            if len(selected) > 1:
                column_title += f" ({len(selected)})"
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
            if item and column in self.editable_columns and self.on_permit_edit(item, column):
                key = item.data(0, self.DataRoles.Contact)
                # this key & find_item business is so we don't hold a reference
                # to the ephemeral item, which may be deleted while the
                # context menu is up.  Accessing the item after on_update runs
                # means the item is deleted and you get a C++ object deleted
                # runtime error.
                menu.addAction(_("Edit {}").format(column_title), lambda: self._on_edit_item(key, column))
            a = menu.addAction(_("Pay to"), lambda: self.parent.payto_contacts(payable_keys))
            a = menu.addAction(_("Delete"), lambda: self.parent.delete_contacts(deletable_keys))
            if not deletable_keys:
                a.setDisabled(True)
            # Add sign/verify and encrypt/decrypt menu - but only if just 1 thing selected
            if len(keys) == 1 and Address.is_valid(keys[0].address):
                signAddr = Address.from_string(keys[0].address)
                a = menu.addAction(_("Sign/verify message") + "...", lambda: self.parent.sign_verify_message(signAddr))
                if signAddr.kind != Address.ADDR_P2PKH:
                    a.setDisabled(True)  # We only allow this for P2PKH since it makes no sense for P2SH (ambiguous public key)
            URLs = [web.BE_URL(self.config, 'addr', Address.from_string(key.address))
                    for key in keys if Address.is_valid(key.address)]
            a = menu.addAction(_("View on block explorer"), lambda: [URL and webopen(URL) for URL in URLs])
            if not any(URLs):
                a.setDisabled(True)
            menu.addSeparator()

        menu.addAction(self.icon_contacts, _("Add Contact") + " - " + _("Address"), self.parent.new_contact_dialog)

        run_hook('create_contact_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    def get_full_contacts(self, include_pseudo: bool = True) -> List[Contact]:
        ''' Returns all the contacts, with the "My CashAcct" pseudo-contacts
        clobbering dupes of the same type that were manually added.
        Client code should scan for type == 'cashacct' and type == 'cashacct_W' '''
        return self.parent.contacts.get_all(nocopy=True)

    @rate_limited(0.333, ts_after=True) # We rate limit the contact list refresh no more 3 per second
    def update(self):
        if self.cleaned_up:
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    def on_update(self):
        if self.cleaned_up:
            return
        item = self.currentItem()
        current_contact = item.data(0, self.DataRoles.Contact) if item else None
        selected = self.selectedItems() or []
        selected_contacts = set(item.data(0, self.DataRoles.Contact) for item in selected)
        del item, selected  # must not hold a reference to a C++ object that will soon be deleted in self.clear()..
        self.clear()
        type_names = defaultdict(lambda: _("Unknown"))
        type_names.update({
            # 'openalias'  : _('OpenAlias'),
            'script'     : _('Script'),
            'address'    : _('Address'),
        })
        type_icons = {
            # 'openalias'  : self.icon_openalias,
            'script'     : self.icon_contacts,
            'address'    : self.icon_contacts,
        }
        selected_items, current_item = [], None
        edited = self._edited_item_cur_sel
        for contact in self.get_full_contacts():
            _type, name, address = contact.type, contact.name, contact.address
            label_key = address
            if _type in ('address'):
                try:
                    # try and re-parse and re-display the address based on current UI string settings
                    addy = Address.from_string(address)
                    address = addy.to_ui_string()
                    label_key = addy.to_storage_string()
                    del addy
                except:
                    ''' This may happen because we may not have always enforced this as strictly as we could have in legacy code. Just move on.. '''
            label = self.wallet.get_label(label_key)
            item = QTreeWidgetItem(["", name, label, address, type_names[_type]])
            item.setData(0, self.DataRoles.Contact, contact)
            item.DataRole = self.DataRoles.Contact
            if _type in type_icons:
                item.setIcon(4, type_icons[_type])
            # always give the "Address" field a monospace font even if it's
            # not strictly an address such as openalias...
            item.setFont(3, self.monospace_font)
            self.addTopLevelItem(item)
            if contact == current_contact or (contact == edited[0] and edited[1]):
                current_item = item  # this key was the current item before and it hasn't gone away
            if contact in selected_contacts or (contact == edited[0] and edited[2]):
                selected_items.append(item)  # this key was selected before and it hasn't gone away

        if selected_items:  # sometimes currentItem is set even if nothing actually selected. grr..
            # restore current item & selections
            if current_item:
                # set the current item. this may also implicitly select it
                self.setCurrentItem(current_item)
            for item in selected_items:
                # restore the previous selection
                item.setSelected(True)
        self._edited_item_cur_sel = (None,) * 3
        run_hook('update_contacts_tab', self)
