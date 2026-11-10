package com.alumiialabs.umbra

import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId

/**
 * The names that an end-to-end test finds a control by. UI Automator reads
 * each one as a resource id. A name says the view and the control, and it
 * holds no data of the user. A change of a name breaks a test, thus a name
 * stays when a label changes.
 */
object TestTags {
    // Each view.
    const val FAULT = "common_fault"
    const val BACK = "common_back"
    const val BAR_TITLE = "common_bar_title"
    const val SHEET = "common_sheet"

    // The first launch and the lock.
    const val UNLOCK_PASSPHRASE = "unlock_passphrase"
    const val UNLOCK_CONFIRM = "unlock_confirm"
    const val UNLOCK_OPEN = "unlock_open"
    const val UNLOCK_RESTORE = "unlock_restore"
    const val UNLOCK_LINK = "unlock_link"

    // The tabs.
    const val TABS_CHATS = "tabs_chats"
    const val TABS_CONTACTS = "tabs_contacts"
    const val TABS_SETTINGS = "tabs_settings"
    const val TABS_ADD = "tabs_add"
    const val TABS_LOCK = "tabs_lock"
    const val TABS_PROFILE = "tabs_profile"
    const val TABS_SEARCH = "tabs_search"

    // The chat list and the contact list.
    const val CHATS_LIST = "chats_list"
    const val CHATS_ROW = "chats_row"
    const val CHATS_ROW_TITLE = "chats_row_title"
    const val CHATS_ROW_UNREAD = "chats_row_unread"
    const val CHATS_EMPTY = "chats_empty"
    const val CHATS_NOTICE = "chats_notice"
    const val CHATS_OPTION_DELETE = "chats_option_delete"
    const val CHATS_OPTION_DETAILS = "chats_option_details"
    const val CONTACTS_LIST = "contacts_list"
    const val CONTACTS_ROW = "contacts_row"

    // A new contact.
    const val ADD_CREATE_INVITATION = "add_create_invitation"
    const val ADD_USE_INVITATION = "add_use_invitation"
    const val ADD_NEW_GROUP = "add_new_group"
    const val INVITE_LINK = "invite_link"
    const val INVITE_COPY = "invite_copy"
    const val INVITE_SHARE = "invite_share"
    const val ACCEPT_SCAN = "accept_scan"
    const val ACCEPT_LINK = "accept_link"
    const val ACCEPT_CONTINUE = "accept_continue"
    const val ACCEPT_SEND_REQUEST = "accept_send_request"
    const val NAME_FIELD = "name_field"
    const val NAME_SAVE = "name_save"
    const val NAME_SKIP = "name_skip"
    const val SCAN_PASTE = "scan_paste"

    // The details of a contact and the verification.
    const val CONTACT_MESSAGE = "contact_message"
    const val CONTACT_VERIFY = "contact_verify"
    const val CONTACT_DELETE = "contact_delete"
    const val CONTACT_BLOCK = "contact_block"
    const val VERIFY_SCAN = "verify_scan"
    const val VERIFY_SHORT_CODE = "verify_short_code"
    const val VERIFY_FULL_NUMBER = "verify_full_number"
    const val VERIFY_CODE = "verify_code"
    const val VERIFY_CODES_MATCH = "verify_codes_match"
    const val VERIFY_CODES_DIFFER = "verify_codes_differ"
    const val VERIFY_DONE = "verify_done"
    const val VERIFY_AGAIN = "verify_again"
    const val SAFETY_NUMBER = "safety_number"
    const val SAFETY_COPY = "safety_copy"
    const val KEY_CHANGE_NUMBER = "key_change_number"
    const val KEY_CHANGE_VERIFY = "key_change_verify"
    const val KEY_CHANGE_ACCEPT = "key_change_accept"

    // A conversation.
    const val CHAT_LIST = "chat_list"
    const val CHAT_SEARCH = "chat_search"
    const val CHAT_INPUT = "chat_input"
    const val CHAT_SEND = "chat_send"
    const val CHAT_ATTACH = "chat_attach"
    const val CHAT_NOTICE = "chat_notice"
    const val CHAT_STOPPED = "chat_stopped"
    const val CHAT_BUBBLE_OUT = "chat_bubble_out"
    const val CHAT_BUBBLE_IN = "chat_bubble_in"
    const val CHAT_BUBBLE_TEXT = "chat_bubble_text"
    const val CHAT_BUBBLE_STATE = "chat_bubble_state"
    const val CHAT_BUBBLE_GONE = "chat_bubble_gone"
    const val CHAT_REACTION = "chat_reaction"
    const val CHAT_NOTE = "chat_note"

    // The sheet of a message.
    const val MESSAGE_REACT = "message_react"
    const val MESSAGE_REPLY = "message_reply"
    const val MESSAGE_EDIT = "message_edit"
    const val MESSAGE_COPY = "message_copy"
    const val MESSAGE_FORWARD = "message_forward"
    const val MESSAGE_SEND_AGAIN = "message_send_again"
    const val MESSAGE_DELETE = "message_delete"
    const val MESSAGE_DELETE_FOR_ME = "message_delete_for_me"
    const val MESSAGE_DELETE_FOR_EVERYONE = "message_delete_for_everyone"
    const val MESSAGE_DELETE_CONFIRM = "message_delete_confirm"

    // The sheet of an attachment.
    const val ATTACH_PHOTO = "attach_photo"
    const val ATTACH_VIDEO = "attach_video"
    const val ATTACH_AUDIO = "attach_audio"
    const val ATTACH_FILE = "attach_file"
    const val ATTACH_POLL = "attach_poll"
    const val ATTACH_CONFIRM = "attach_confirm"

    // A group.
    const val GROUP_NAME = "group_name"
    const val GROUP_CREATE = "group_create"
    const val GROUP_ADD_MEMBERS = "group_add_members"
    const val GROUP_INVITE_ROW = "group_invite_row"
    const val GROUP_MEMBER_ROW = "group_member_row"
    const val GROUP_MEMBER_ROLE = "group_member_role"
    const val GROUP_MEMBER_REMOVE = "group_member_remove"
    const val GROUP_REMOVE_CONFIRM = "group_remove_confirm"
    const val GROUP_LEAVE = "group_leave"
    const val GROUP_LEAVE_CONFIRM = "group_leave_confirm"
    const val GROUP_LET_IN = "group_let_in"
    const val GROUP_OFFER_JOIN = "group_offer_join"

    // A poll.
    const val POLL_QUESTION = "poll_question"
    const val POLL_OPTION = "poll_option"
    const val POLL_ADD_OPTION = "poll_add_option"
    const val POLL_SEND = "poll_send"
    const val POLL_CHOICE = "poll_choice"

    // The devices of the set.
    const val DEVICES_LINK = "devices_link"
    const val DEVICES_ROW = "devices_row"
    const val DEVICES_REMOVE = "devices_remove"
    const val LINK_TICKET = "link_ticket"
    const val LINK_COPY = "link_copy"
    const val LINK_CODE = "link_code"
    const val LINK_CODES_MATCH = "link_codes_match"
    const val LINK_CODES_DIFFER = "link_codes_differ"
    const val LINK_DONE = "link_done"
    const val LINK_AGAIN = "link_again"
    const val JOIN_PASSPHRASE = "join_passphrase"
    const val JOIN_CONFIRM = "join_confirm"
    const val JOIN_NEXT = "join_next"
    const val JOIN_PASTE_INSTEAD = "join_paste_instead"
    const val JOIN_TICKET = "join_ticket"
    const val JOIN_LINK = "join_link"
    const val JOIN_CODE = "join_code"
    const val JOIN_BACK = "join_back"

    // The backup and the restore.
    const val RECOVERY_DIGITS = "recovery_digits"
    const val RECOVERY_ROOT_SEED = "recovery_root_seed"
    const val RECOVERY_SOCIAL = "recovery_social"
    const val RESTORE_CODE = "restore_code"
    const val RESTORE_PASSPHRASE = "restore_passphrase"
    const val RESTORE_CONFIRM = "restore_confirm"
    const val RESTORE_START = "restore_start"
    const val RESTORE_BACK = "restore_back"
    const val RESTORE_STATE = "restore_state"

    // The settings.
    const val SETTINGS_APPEARANCE = "settings_appearance"
    const val SETTINGS_NOTIFICATIONS = "settings_notifications"
    const val SETTINGS_TYPING = "settings_typing"
    const val SETTINGS_DRAFT_SYNC = "settings_draft_sync"
    const val SETTINGS_HISTORY = "settings_history"
    const val SETTINGS_DOWNLOAD = "settings_download"
    const val SETTINGS_PASSPHRASE = "settings_passphrase"
    const val SETTINGS_AUTO_LOCK = "settings_auto_lock"
    const val SETTINGS_RECOVERY = "settings_recovery"
    const val SETTINGS_DEVICES = "settings_devices"
    const val SETTINGS_RESET = "settings_reset"
    const val SETTINGS_ERASE = "settings_erase"
    const val SETTINGS_ERASE_CONFIRM = "settings_erase_confirm"
    const val PASSPHRASE_CURRENT = "passphrase_current"
    const val PASSPHRASE_NEW = "passphrase_new"
    const val PASSPHRASE_CONFIRM = "passphrase_confirm"
    const val PASSPHRASE_SAVE = "passphrase_save"
}

/** Puts a test name on a control, or nothing when the caller gives none. */
fun Modifier.tagged(tag: String?): Modifier = if (tag == null) this else testTag(tag)

/**
 * Makes each test name under this node a resource id for UI Automator. The
 * root of each window sets it one time: the activity, a sheet, and a dialog.
 */
@OptIn(ExperimentalComposeUiApi::class)
fun Modifier.testRoot(): Modifier = semantics { testTagsAsResourceId = true }
