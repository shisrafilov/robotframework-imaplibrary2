#!/usr/bin/env python
# -*- coding: utf-8 -*-

#    Copyright 2015-2016 Richard Huang <rickypc@users.noreply.github.com>
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""
IMAP Library - a IMAP email testing library.
"""

from sys import path
path.append('src')
from ImapLibrary2 import ImapLibrary2
import mock
import unittest


class ImapLibrary2Tests(unittest.TestCase):
    """Imap library test class."""

    def setUp(self):
        """Instantiate the Imap library class."""
        self.library = ImapLibrary2()
        self.password = 'password'
        self.port = 143
        self.port_secure = 993
        self.recipient = 'my@domain.com'
        self.sender = 'noreply@domain.com'
        self.server = 'my.imap'
        self.status = 'UNSEEN'
        self.subject = 'subject'
        self.text = 'text'
        self.username = 'username'
        self.folder = 'INBOX'
        self.folder_check = '"INBOX"'
        self.folder_filter = '"OUTBOX"'

    def test_should_have_default_values(self):
        """Imap library instance should have default values set."""
        self.assertIsInstance(self.library, ImapLibrary2)
        self.assertIsNone(self.library._email_index)
        self.assertIsNone(self.library._imap)
        self.assertIsInstance(self.library._mails, list)
        self.assertIsNone(self.library._mp_iter)
        self.assertIsNone(self.library._mp_msg)
        self.assertIsNone(self.library._part)
        self.assertEqual(self.library.PORT, self.port)
        self.assertEqual(self.library.PORT_SECURE, self.port_secure)
        self.assertEqual(self.library.FOLDER, self.folder)

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_open_secure_mailbox(self, mock_imap):
        """Open mailbox should open secure connection to IMAP server
        with requested credentials.
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        mock_imap.assert_called_with(self.server, self.port_secure)
        self.library._imap.login.assert_called_with(self.username, self.password)
        self.library._imap.select.assert_called_with(self.folder_check)

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_open_secure_mailbox_with_custom_port(self, mock_imap):
        """Open mailbox should open secure connection to IMAP server
        with requested credentials and custom port.
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password, port=8000)
        mock_imap.assert_called_with(self.server, 8000)
        self.library._imap.login.assert_called_with(self.username, self.password)
        self.library._imap.select.assert_called_with(self.folder_check)

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_open_secure_mailbox_with_custom_folder(self, mock_imap):
        """Open mailbox should open secure connection to IMAP server with
        requested credentials to a custom folder
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password, folder='Outbox')
        mock_imap.assert_called_with(self.server, self.port_secure)
        self.library._imap.login.assert_called_with(self.username, self.password)
        self.library._imap.select.assert_called_with('"Outbox"')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_open_secure_mailbox_with_server_key(self, mock_imap):
        """Open mailbox should open secure connection to IMAP server
        using 'server' key with requested credentials.
        """
        self.library.open_mailbox(server=self.server, user=self.username,
                                  password=self.password)
        mock_imap.assert_called_with(self.server, self.port_secure)
        self.library._imap.login.assert_called_with(self.username, self.password)
        self.library._imap.select.assert_called_with(self.folder_check)

    @mock.patch('ImapLibrary2.IMAP4')
    def test_should_open_non_secure_mailbox(self, mock_imap):
        """Open mailbox should open non-secure connection to IMAP server
        with requested credentials.
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password, is_secure=False)
        mock_imap.assert_called_with(self.server, self.port)
        self.library._imap.login.assert_called_with(self.username, self.password)
        self.library._imap.select.assert_called_with(self.folder_check)

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index(self, mock_imap):
        """Returns email index from connected IMAP session."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email(sender=self.sender)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'FROM',
                                                    '"%s"' % self.sender)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_with_sender_filter(self, mock_imap):
        """Returns email index from connected IMAP session
        with sender filter.
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email(sender=self.sender)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'FROM',
                                                    '"%s"' % self.sender)
        self.assertEqual(index, '0')
        index = self.library.wait_for_email(from_email=self.sender)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'FROM',
                                                    '"%s"' % self.sender)
        self.assertEqual(index, '0')
        index = self.library.wait_for_email(fromEmail=self.sender)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'FROM',
                                                    '"%s"' % self.sender)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_with_recipient_filter(self, mock_imap):
        """Returns email index from connected IMAP session
        with recipient filter.
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email(recipient=self.recipient)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'TO',
                                                     '"%s"' % self.recipient)
        self.assertEqual(index, '0')
        index = self.library.wait_for_email(to_email=self.recipient)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'TO',
                                                     '"%s"' % self.recipient)
        self.assertEqual(index, '0')
        index = self.library.wait_for_email(toEmail=self.recipient)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'TO',
                                                     '"%s"' % self.recipient)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_with_subject_filter(self, mock_imap):
        """Returns email index from connected IMAP session
        with subject filter.
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email(subject=self.subject)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'SUBJECT',
                                                     '"%s"' % self.subject)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_with_text_filter(self, mock_imap):
        """Returns email index from connected IMAP session with text filter."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email(text=self.text)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'TEXT',
                                                     '"%s"' % self.text)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_with_status_filter(self, mock_imap):
        """Returns email index from connected IMAP session with status filter."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email(status=self.status)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, self.status)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_with_folder_filter(self, mock_imap):
        """Returns email index from connected IMAP session with
        folder filter.
        """
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email(folder='OUTBOX')
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        self.library._imap.select.assert_called_with(self.folder_filter)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_without_filter(self, mock_imap):
        """Returns email index from connected IMAP session without filter."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['0']]
        index = self.library.wait_for_email()
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, self.status)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_return_email_index_after_delay(self, mock_imap):
        """Returns email index from connected IMAP session after some delay."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.side_effect = [['OK', ['']], ['OK', ['0']]]
        index = self.library.wait_for_email(sender=self.sender, poll_frequency=0.2)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'FROM',
                                                     '"%s"' % self.sender)
        self.assertEqual(index, '0')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_raise_exception_on_timeout(self, mock_imap):
        """Raise exception on timeout."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['OK', ['']]
        with self.assertRaises(AssertionError) as context:
            self.library.wait_for_email(sender=self.sender, poll_frequency=0.2,
                                        timeout=0.3)
            self.assertTrue("No email received within 0s" in context.exception)
        self.library._imap.select.assert_called_with(self.folder_check)

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_raise_exception_on_select_error(self, mock_imap):
        """Raise exception on imap select error."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['NOK', ['1']]
        with self.assertRaises(Exception) as context:
            self.library.wait_for_email(sender=self.sender)
            self.assertTrue("imap.select error: NOK, ['1']" in context.exception)
        self.library._imap.select.assert_called_with(self.folder_check)

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_raise_exception_on_search_error(self, mock_imap):
        """Raise exception on imap search error."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library._imap.select.return_value = ['OK', ['1']]
        self.library._imap.uid.return_value = ['NOK', ['']]
        with self.assertRaises(Exception) as context:
            self.library.wait_for_email(sender=self.sender)
            self.assertTrue("imap.search error: NOK, [''], criteria=['FROM', '%s']" %
                            self.sender in context.exception)
        self.library._imap.select.assert_called_with(self.folder_check)
        self.library._imap.uid.assert_called_with('search', None, 'FROM', '"%s"' %
                                                     self.sender)

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_delete_email(self, mock_imap):
        """Delete specific email."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library.delete_email('0')
        self.library._imap.uid.assert_called_with('store', '0', '+FLAGS', r'(\DELETED)')
        self.library._imap.expunge.assert_called_with()

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_mark_email_as_read(self, mock_imap):
        """Mark specific email as read."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library.mark_email_as_read('0')
        self.library._imap.uid.assert_called_with('store', '0', '+FLAGS', r'\SEEN')

    @mock.patch('ImapLibrary2.IMAP4_SSL')
    def test_should_close_mailbox(self, mock_imap):
        """Close opened connection."""
        self.library.open_mailbox(host=self.server, user=self.username,
                                  password=self.password)
        self.library.close_mailbox()
        self.library._imap.close.assert_called_with()
