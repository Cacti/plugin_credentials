<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

chdir('../../');

include('./include/auth.php');
include_once('./plugins/credentials/includes/arrays.php');
include_once('./plugins/credentials/includes/functions.php');

/* access to this page is gated on the core Users/Groups realm (realm 1) via
 * $user_auth_realm_filenames in setup.php; re-assert it here defensively. */
if (!is_realm_allowed(1)) {
	header('Location: permission_denied.php');

	exit;
}

$actions = array(
	1 => __('Delete', 'credentials'),
	2 => __('Enable', 'credentials'),
	3 => __('Disable', 'credentials'),
);

set_default_action();

switch (get_request_var('action')) {
	case 'save':
		form_save();

		break;
	case 'actions':
		form_actions();

		break;
	case 'edit':
		top_header();

		credentials_edit();

		bottom_footer();

		break;
	default:
		top_header();

		credentials_list();

		bottom_footer();

		break;
}

/**
 * Persist a credential from the edit form. Secret fields are encrypted with the
 * Cacti core secret functions; a blank secret on an existing credential keeps
 * the previously stored value. Switching the credential type replaces the
 * type-specific properties entirely (the user is warned client-side first).
 *
 * @return void
 */
function form_save(): void {
	/* saving changes state: require POST so the request carries Cacti's CSRF
	 * token and cannot be triggered through a crafted GET link */
	if (!isset($_SERVER['REQUEST_METHOD']) || strtoupper($_SERVER['REQUEST_METHOD']) !== 'POST') {
		header('Location: credentials.php');

		exit;
	}

	if (!isset_request_var('save_component_credential')) {
		header('Location: credentials.php');

		exit;
	}

	get_filter_request_var('id');

	$id   = get_nfilter_request_var('id');
	$type = get_nfilter_request_var('type');

	$definition = credentials_get_type($type);

	if ($definition === false) {
		raise_message('cred_badtype', __('The selected credential type is not valid.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : ''));

		exit;
	}

	$name = trim(get_nfilter_request_var('name'));

	if ($name == '') {
		raise_message('cred_noname', __('A credential name is required.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

		exit;
	}

	/* the secret provider backing this credential: 0 = local encrypted store,
	 * otherwise a credential_providers row whose driver resolves references */
	$provider_id = isset_request_var('provider_id') ? (int) get_nfilter_request_var('provider_id') : 0;

	if ($provider_id > 0) {
		$provider_row = db_fetch_row_prepared('SELECT id, enabled FROM credential_providers WHERE id = ?', array($provider_id));

		if (!is_array($provider_row) || !cacti_sizeof($provider_row)) {
			raise_message('cred_badprovider', __('The selected secret provider does not exist.', 'credentials'), MESSAGE_LEVEL_ERROR);
			header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

			exit;
		}

		if ($provider_row['enabled'] != 'on') {
			raise_message('cred_disprovider', __('The selected secret provider is disabled.', 'credentials'), MESSAGE_LEVEL_ERROR);
			header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

			exit;
		}
	}

	$use_provider = ($provider_id > 0);

	/* previous row + properties, used to preserve unchanged secrets */
	$prev_props = array();
	$prev_type  = '';
	$prev_owner = 0;

	if (!empty($id)) {
		$existing = db_fetch_row_prepared('SELECT * FROM credentials WHERE id = ?', array($id));

		if (is_array($existing) && cacti_sizeof($existing)) {
			$prev_type     = $existing['type'];
			$prev_owner    = $existing['user_id'];
			$prev_provider = isset($existing['provider_id']) ? (int) $existing['provider_id'] : 0;

			/* only reuse stored properties when BOTH the type and the backing
			 * provider are unchanged; otherwise the stored secret fields hold a
			 * different kind of value (local ciphertext vs. provider reference)
			 * and a blank input must not silently preserve the old value */
			if ($prev_type == $type && $prev_provider == $provider_id) {
				$prev_props = credentials_properties($existing);
			}
		}
	}

	/* if any secret is being set and core encryption is unavailable, fail closed
	 * - provider-backed credentials store references, so they never encrypt */
	$needs_encryption = false;

	if (!$use_provider) {
		foreach ($definition['fields'] as $fname => $field) {
			if (!empty($field['secret'])) {
				$posted = isset_request_var($fname) ? get_nfilter_request_var($fname) : '';

				if ($posted !== '') {
					$needs_encryption = true;
				}
			}
		}
	}

	if ($needs_encryption && !credentials_encryption_available()) {
		raise_message('cred_noenc', __('Cannot store a secret: the Cacti core secret encryption functions are unavailable on this installation.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

		exit;
	}

	$props = array();

	foreach ($definition['fields'] as $fname => $field) {
		$is_secret = !empty($field['secret']);

		if ($is_secret) {
			$posted = isset_request_var($fname) ? get_nfilter_request_var($fname) : '';

			if ($use_provider) {
				/* a provider-backed secret stores a reference (a path/locator),
				 * not ciphertext: keep it in clear, it is not itself a secret */
				if ($posted === '' && !empty($field['required'])) {
					raise_message('cred_req_' . $fname, __('A reference for \'%s\' is required.', $field['friendly_name'], 'credentials'), MESSAGE_LEVEL_ERROR);
					header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type . '&provider_id=' . $provider_id);

					exit;
				}

				$props[$fname] = $posted;

				continue;
			}

			/* short secrets (textbox_password) require a matching confirm box */
			if (empty($field['long'])) {
				$confirm = isset_request_var($fname . '_confirm') ? get_nfilter_request_var($fname . '_confirm') : $posted;

				if ($posted !== $confirm) {
					raise_message('cred_mismatch', __('The value and its confirmation for \'%s\' do not match.', $field['friendly_name'], 'credentials'), MESSAGE_LEVEL_ERROR);
					header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

					exit;
				}
			}

			if ($posted === '') {
				/* keep the existing encrypted value when left blank */
				if (isset($prev_props[$fname]) && $prev_props[$fname] !== '') {
					$props[$fname] = $prev_props[$fname];
				} elseif (!empty($field['required'])) {
					/* required with no preserved value (new, or a type switch cleared it) */
					raise_message('cred_req_' . $fname, __('\'%s\' is required.', $field['friendly_name'], 'credentials'), MESSAGE_LEVEL_ERROR);
					header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

					exit;
				}
			} else {
				list($enc_ok, $enc_val) = credentials_try_encrypt($posted);

				if (!$enc_ok) {
					raise_message('cred_encfail', __('Could not encrypt the secret. Verify the Cacti encryption key configuration and try again.', 'credentials'), MESSAGE_LEVEL_ERROR);
					header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

					exit;
				}

				$props[$fname] = $enc_val;
			}
		} else {
			$value = isset_request_var($fname) ? get_nfilter_request_var($fname) : '';

			/* constrain drop_array values to their declared options */
			if ($field['method'] == 'drop_array' && isset($field['array']) && !array_key_exists($value, $field['array'])) {
				$value = isset($field['default']) ? $field['default'] : '';
			}

			if ($value === '' && !empty($field['required'])) {
				raise_message('cred_req_' . $fname, __('\'%s\' is required.', $field['friendly_name'], 'credentials'), MESSAGE_LEVEL_ERROR);
				header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

				exit;
			}

			$props[$fname] = $value;
		}
	}

	$cross_error = credentials_cross_field_error($type, $props);

	if ($cross_error !== '') {
		raise_message('cred_cross', $cross_error, MESSAGE_LEVEL_ERROR);
		header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

		exit;
	}

	$encoded_props = json_encode($props);

	/* an invalid-UTF-8 byte in any field makes json_encode() return false; refuse
	   to persist it so sql_save() cannot blank the stored properties - including
	   the encrypted secrets preserved above - while still reporting success */
	if ($encoded_props === false) {
		raise_message('cred_encode', __('The credential could not be saved because one of its fields contains invalid characters. Please re-enter the affected values and try again.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

		exit;
	}

	$save                = array();
	$save['id']          = $id;
	$save['name']        = $name;
	$save['description'] = get_nfilter_request_var('description');
	$save['type']        = $type;
	$save['provider_id'] = $provider_id;
	$save['enabled']     = isset_request_var('enabled') ? 'on' : '';
	$save['properties']  = $encoded_props;

	/* preserve the original owner on edit; stamp the current user on create */
	if (!empty($id) && !empty($prev_owner)) {
		$save['user_id'] = $prev_owner;
	} else {
		$save['user_id'] = (isset($_SESSION['sess_user_id']) ? $_SESSION['sess_user_id'] : 0);
	}

	if ($provider_id > 0) {
		/* persist under a transaction that locks the provider row, so a
		 * concurrent provider delete (which locks the same row before counting
		 * references) cannot remove it between validation and save and leave
		 * this credential pointing at a missing provider */
		db_execute('START TRANSACTION');

		$locked = db_fetch_row_prepared('SELECT id, enabled FROM credential_providers WHERE id = ? FOR UPDATE', array($provider_id));

		if (!is_array($locked) || !cacti_sizeof($locked) || $locked['enabled'] != 'on') {
			db_execute('ROLLBACK');
			raise_message('cred_provgone', __('The selected secret provider is no longer available. Please choose another provider.', 'credentials'), MESSAGE_LEVEL_ERROR);
			header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

			exit;
		}

		$new_id = sql_save($save, 'credentials');

		db_execute('COMMIT');
	} else {
		$new_id = sql_save($save, 'credentials');
	}

	if ($new_id) {
		raise_message('cred_saved', __('Credential saved.', 'credentials'), MESSAGE_LEVEL_INFO);
		header('Location: credentials.php?action=edit&id=' . $new_id);
	} else {
		raise_message('cred_savefail', __('Failed to save the credential.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credentials.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);
	}

	exit;
}

/**
 * Process the bulk action form (delete / enable / disable) against the selected
 * credentials.
 *
 * @return void
 */
function form_actions(): void {
	global $actions;

	/* bulk actions are state-changing: require POST so the request carries
	 * Cacti's CSRF token and cannot be triggered through a crafted GET */
	if (!isset($_SERVER['REQUEST_METHOD']) || strtoupper($_SERVER['REQUEST_METHOD']) !== 'POST') {
		header('Location: credentials.php');

		exit;
	}

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items != false) {
			$action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				$id = intval($id);

				if ($action == '1') {
					db_execute_prepared('DELETE FROM credentials WHERE id = ?', array($id));
				} elseif ($action == '2') {
					db_execute_prepared('UPDATE credentials SET enabled = \'on\' WHERE id = ?', array($id));
				} elseif ($action == '3') {
					db_execute_prepared('UPDATE credentials SET enabled = \'\' WHERE id = ?', array($id));
				}
			}
		}

		header('Location: credentials.php');

		exit;
	}

	/* confirmation list. The checked rows arrive as chk_<id> fields - Cacti's
	 * standard bulk-selection mechanism (see core user_domains.php). Validate
	 * each id through the Cacti request API and bind them as prepared params. */
	$ids   = array();
	$items = '';

	foreach (array_keys($_POST) as $var) {
		if (preg_match('/^chk_([0-9]+)$/', $var, $matches)) {
			input_validate_input_number($matches[1], 'chk_id');
			$ids[] = (int) $matches[1];
		}
	}

	$drp_action = get_nfilter_request_var('drp_action');

	if (!isset($actions[$drp_action])) {
		header('Location: credentials.php');

		exit;
	}

	top_header();

	form_start('credentials.php');

	html_start_box($actions[$drp_action], '60%', '', '3', 'center', '');

	if (cacti_sizeof($ids)) {
		$placeholders = implode(',', array_fill(0, cacti_sizeof($ids), '?'));
		$names        = db_fetch_assoc_prepared("SELECT id, name FROM credentials WHERE id IN ($placeholders) ORDER BY name", $ids);

		foreach ($names as $row) {
			$items .= '<li>' . html_escape($row['name']) . '</li>';
		}
	}

	if ($drp_action == '1') {
		$title = __('Delete the following credential(s)?', 'credentials');
	} elseif ($drp_action == '2') {
		$title = __('Enable the following credential(s)?', 'credentials');
	} else {
		$title = __('Disable the following credential(s)?', 'credentials');
	}

	print "<tr>
		<td class='textArea'>
			<p>$title</p>
			<ul>$items</ul>
		</td>
	</tr>";

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'credentials') . "' onClick='cactiReturnTo()'>&nbsp;<input type='submit' class='ui-button ui-corner-all ui-widget' value='" . __esc('Continue', 'credentials') . "'>";

	print "<tr>
		<td class='saveRow' colspan='2'>
			<input type='hidden' name='action' value='actions'>
			<input type='hidden' name='selected_items' value='" . (isset($ids) ? html_escape(serialize($ids)) : '') . "'>
			<input type='hidden' name='drp_action' value='" . html_escape($drp_action) . "'>
			$save_html
		</td>
	</tr>";

	html_end_box();

	form_end();

	bottom_footer();
}

/**
 * Render the credential list with filtering, sorting, paging and bulk actions.
 *
 * @return void
 */
function credentials_list(): void {
	global $actions;

	$filters = array(
		'rows' => array(
			'filter'  => FILTER_VALIDATE_INT,
			'default' => read_config_option('num_rows_table'),
		),
		'page' => array(
			'filter'  => FILTER_VALIDATE_INT,
			'default' => '1',
		),
		'filter' => array(
			'filter'  => FILTER_DEFAULT,
			'default' => '',
		),
		'type' => array(
			'filter'  => FILTER_DEFAULT,
			'default' => '',
		),
		'sort_column' => array(
			'filter'  => FILTER_CALLBACK,
			'default' => 'name',
			'options' => array('options' => 'sanitize_search_string'),
		),
		'sort_direction' => array(
			'filter'  => FILTER_CALLBACK,
			'default' => 'ASC',
			'options' => array('options' => 'sanitize_search_string'),
		),
	);

	validate_store_request_vars($filters, 'sess_cred');

	$allowed_sort = array(
		'name'         => 'c.name',
		'type'         => 'c.type',
		'provider'     => 'provider',
		'description'  => 'c.description',
		'enabled'      => 'c.enabled',
		'owner'        => 'owner',
		'last_updated' => 'c.last_updated',
	);

	$sort_key    = get_request_var('sort_column');
	$sort_column = isset($allowed_sort[$sort_key]) ? $allowed_sort[$sort_key] : 'c.name';
	$sort_dir    = (strtoupper(get_request_var('sort_direction')) == 'DESC') ? 'DESC' : 'ASC';

	$sql_where = '';
	$params    = array();

	if (get_request_var('filter') != '') {
		$sql_where = 'WHERE (c.name LIKE ? OR c.description LIKE ?)';
		$params[]  = '%' . get_request_var('filter') . '%';
		$params[]  = '%' . get_request_var('filter') . '%';
	}

	if (get_request_var('type') != '' && credentials_get_type(get_request_var('type')) !== false) {
		$sql_where .= ($sql_where == '' ? 'WHERE ' : ' AND ') . 'c.type = ?';
		$params[]   = get_request_var('type');
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*)
		FROM credentials AS c
		$sql_where", $params);

	$rows_per_page = get_request_var('rows');

	if ($rows_per_page == -1) {
		$rows_per_page = $total_rows;
	}

	$rows_per_page = max(1, (int) $rows_per_page);
	$page          = max(1, (int) get_request_var('page'));
	$sql_limit     = ' LIMIT ' . ($rows_per_page * ($page - 1)) . ',' . $rows_per_page;

	$credentials = db_fetch_assoc_prepared("SELECT c.*, ua.username AS owner, cp.name AS provider
		FROM credentials AS c
		LEFT JOIN user_auth AS ua
		ON ua.id = c.user_id
		LEFT JOIN credential_providers AS cp
		ON cp.id = c.provider_id
		$sql_where
		ORDER BY $sort_column $sort_dir
		$sql_limit", $params);

	$types = credentials_types();

	?>
	<script type='text/javascript' <?php print credentials_csp_nonce();?>>
	function applyFilter() {
		strURL  = 'credentials.php?header=false';
		strURL += '&filter=' + encodeURIComponent($('#filter').val());
		strURL += '&type='   + encodeURIComponent($('#type').val());
		strURL += '&rows='   + encodeURIComponent($('#rows').val());
		strURL += '&page=1';
		loadPageNoHeader(strURL);
	}

	function clearFilter() {
		strURL = 'credentials.php?clear=true&header=false';
		loadPageNoHeader(strURL);
	}

	$(function() {
		$('#refresh').click(function() { applyFilter(); });
		$('#clear').click(function() { clearFilter(); });
		$('#form_credentials').submit(function(event) {
			event.preventDefault();
			applyFilter();
		});
	});
	</script>
	<?php

	html_start_box(__('Credentials', 'credentials'), '100%', '', '3', 'center', 'credentials.php?action=edit');

	?>
	<tr class='even noprint'>
		<td>
		<form id='form_credentials' action='credentials.php' method='get'>
			<table class='filterTable'>
				<tr>
					<td><?php print __('Search', 'credentials');?></td>
					<td>
						<input type='text' class='ui-state-default ui-corner-all' id='filter' size='30' value='<?php print html_escape(get_request_var('filter'));?>'>
					</td>
					<td><?php print __('Type', 'credentials');?></td>
					<td>
						<select id='type'>
							<option value=''<?php if (get_request_var('type') == '') { print ' selected'; }?>><?php print __('Any', 'credentials');?></option>
							<?php
							foreach (credentials_type_options() as $code => $label) {
								print "<option value='" . html_escape($code) . "'" . (get_request_var('type') == $code ? ' selected' : '') . '>' . html_escape($label) . '</option>';
							}
							?>
						</select>
					</td>
					<td><?php print __('Credentials', 'credentials');?></td>
					<td>
						<select id='rows'>
							<option value='-1'<?php if (get_request_var('rows') == '-1') { print ' selected'; }?>><?php print __('All', 'credentials');?></option>
							<?php
							$row_options = array(10, 20, 30, 50, 100, 250, 500);
							foreach ($row_options as $r) {
								print "<option value='$r'" . (get_request_var('rows') == $r ? ' selected' : '') . ">$r</option>";
							}
							?>
						</select>
					</td>
					<td>
						<span>
							<input type='button' class='ui-button ui-corner-all ui-widget' id='refresh' value='<?php print __esc('Go', 'credentials');?>'>
							<input type='button' class='ui-button ui-corner-all ui-widget' id='clear' value='<?php print __esc('Clear', 'credentials');?>'>
						</span>
					</td>
				</tr>
			</table>
		</form>
		</td>
	</tr>
	<?php

	html_end_box();

	$nav = html_nav_bar('credentials.php', MAX_DISPLAY_PAGES, $page, $rows_per_page, $total_rows, 7, __('Credentials', 'credentials'), 'page', 'main');

	print $nav;

	form_start('credentials.php', 'chk');

	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'name'         => array('display' => __('Name', 'credentials'),         'sort' => 'ASC', 'align' => 'left'),
		'type'         => array('display' => __('Type', 'credentials'),         'sort' => 'ASC', 'align' => 'left'),
		'provider'     => array('display' => __('Secret Provider', 'credentials'), 'sort' => 'ASC', 'align' => 'left'),
		'description'  => array('display' => __('Description', 'credentials'),   'sort' => 'ASC', 'align' => 'left', 'nohide' => true),
		'owner'        => array('display' => __('Owner', 'credentials'),        'sort' => 'ASC', 'align' => 'left'),
		'enabled'      => array('display' => __('Enabled', 'credentials'),      'sort' => 'ASC', 'align' => 'left'),
		'last_updated' => array('display' => __('Last Updated', 'credentials'), 'sort' => 'DESC', 'align' => 'left'),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	if (cacti_sizeof($credentials)) {
		foreach ($credentials as $row) {
			$type_name     = isset($types[$row['type']]) ? $types[$row['type']]['name'] : $row['type'];
			$provider_name = ($row['provider_id'] > 0 && $row['provider'] != '') ? $row['provider'] : __('Local Database', 'credentials');

			form_alternate_row('line' . $row['id'], true);

			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('credentials.php?action=edit&id=' . $row['id']) . '">' . html_escape($row['name']) . '</a>', $row['id']);
			form_selectable_cell(html_escape($type_name), $row['id']);
			form_selectable_cell(html_escape($provider_name), $row['id']);
			form_selectable_cell(html_escape($row['description']), $row['id']);
			form_selectable_cell(html_escape($row['owner'] != '' ? $row['owner'] : __('N/A', 'credentials')), $row['id']);
			form_selectable_cell($row['enabled'] == 'on' ? __('Yes', 'credentials') : __('No', 'credentials'), $row['id']);
			form_selectable_cell(html_escape($row['last_updated']), $row['id']);
			form_checkbox_cell($row['name'], $row['id']);

			form_end_row();
		}
	} else {
		print "<tr class='tableRow odd'><td colspan='8'><em>" . __('No Credentials Found', 'credentials') . '</em></td></tr>';
	}

	html_end_box(false);

	if (cacti_sizeof($credentials)) {
		print $nav;
	}

	draw_actions_dropdown($actions);

	form_end();
}

/**
 * Render the add/edit form for a single credential. Base fields (name,
 * description, type, enabled) are followed by the fields specific to the
 * selected credential type; secret fields are rendered masked.
 *
 * @return void
 */
function credentials_edit(): void {
	global $config;

	get_filter_request_var('id');

	$id  = isempty_request_var('id') ? 0 : get_request_var('id');
	$row = array('id' => 0, 'name' => '', 'description' => '', 'type' => '', 'provider_id' => 0, 'enabled' => 'on');

	if (!empty($id)) {
		$fetched = db_fetch_row_prepared('SELECT * FROM credentials WHERE id = ?', array($id));

		if (is_array($fetched) && cacti_sizeof($fetched)) {
			$row = $fetched;
		} else {
			$id = 0;
		}
	}

	$props = credentials_properties($row);

	$options = credentials_type_options();

	/* the displayed type: an explicit ?type= (type switch) wins, else the
	 * stored type, else the first available type for a brand-new credential */
	if (isset_request_var('type') && credentials_get_type(get_nfilter_request_var('type')) !== false) {
		$type = get_nfilter_request_var('type');
	} elseif ($row['type'] != '' && credentials_get_type($row['type']) !== false) {
		$type = $row['type'];
	} else {
		$type = key($options);
	}

	/* if the shown type differs from the stored type, the stored properties do
	 * not apply to the fields we are about to render */
	if ($type != $row['type']) {
		$props = array();
	}

	/* the displayed secret provider: an explicit ?provider_id= (provider switch)
	 * wins, else the stored provider, else the local encrypted store (0) */
	$stored_provider = isset($row['provider_id']) ? (int) $row['provider_id'] : 0;
	$provider_opts   = credentials_provider_options($stored_provider);

	if (isset_request_var('provider_id')) {
		$provider_id = (int) get_nfilter_request_var('provider_id');
	} else {
		$provider_id = $stored_provider;
	}

	if (!isset($provider_opts[$provider_id])) {
		$provider_id = 0;
	}

	/* switching the backing provider changes how secret fields are rendered
	 * (masked local secrets vs. plain references), so the stored secret values
	 * no longer apply; drop them while keeping the non-secret field values */
	if ($provider_id != $stored_provider && is_array(credentials_get_type($type))) {
		foreach (credentials_get_type($type)['fields'] as $sname => $sf) {
			if (!empty($sf['secret'])) {
				unset($props[$sname]);
			}
		}
	}

	$provider_driver = $provider_id > 0 ? credentials_provider_driver(db_fetch_cell_prepared('SELECT type FROM credential_providers WHERE id = ?', array($provider_id))) : null;

	$definition = credentials_get_type($type);

	$header = ($id > 0) ? __esc('Credential [edit: %s]', $row['name'], 'credentials') : __('Credential [new]', 'credentials');

	$fields = array(
		'name' => array(
			'method'        => 'textbox',
			'friendly_name' => __('Name', 'credentials'),
			'description'   => __('A unique, meaningful name for this credential.', 'credentials'),
			'value'         => $row['name'],
			'max_length'    => 128,
			'size'          => 60,
		),
		'description' => array(
			'method'        => 'textbox',
			'friendly_name' => __('Description', 'credentials'),
			'description'   => __('An optional description of where this credential is used.', 'credentials'),
			'value'         => $row['description'],
			'max_length'    => 255,
			'size'          => 60,
		),
		'type' => array(
			'method'        => 'drop_array',
			'friendly_name' => __('Credential Type', 'credentials'),
			'description'   => __('The type of credential. Changing the type on an existing credential discards the previously stored type-specific values when you save.', 'credentials'),
			'value'         => $type,
			'array'         => $options,
		),
		'provider_id' => array(
			'method'        => 'drop_array',
			'friendly_name' => __('Secret Provider', 'credentials'),
			'description'   => __('Where the secret values for this credential live. Choose the local encrypted database, or an external secret store. When an external provider is selected, each secret field holds a reference the provider resolves at poll time instead of the secret itself.', 'credentials'),
			'value'         => $provider_id,
			'array'         => $provider_opts,
		),
		'enabled' => array(
			'method'        => 'checkbox',
			'friendly_name' => __('Enabled', 'credentials'),
			'description'   => __('Whether this credential is available for use.', 'credentials'),
			'value'         => $row['enabled'],
			'default'       => 'on',
			'form_id'       => $id,
		),
	);

	if (is_array($definition)) {
		foreach ($definition['fields'] as $fname => $f) {
			$is_secret      = !empty($f['secret']);
			$render_as_ref  = $is_secret && $provider_id > 0;

			$field = array(
				'friendly_name' => $f['friendly_name'] . (!empty($f['required']) ? ' *' : ''),
				'method'        => $render_as_ref ? 'textbox' : $f['method'],
				'description'   => $f['description'],
			);

			if ($field['method'] == 'drop_array') {
				$field['array'] = $f['array'];

				if (isset($f['default'])) {
					$field['default'] = $f['default'];
				}
			}

			if ($field['method'] == 'textbox' || $field['method'] == 'textbox_password') {
				$field['max_length'] = $render_as_ref ? 1024 : (isset($f['max_length']) ? $f['max_length'] : 255);
				$field['size']       = 60;
			}

			if ($field['method'] == 'textarea') {
				$field['textarea_rows'] = 6;
				$field['textarea_cols'] = 60;
				$field['class']         = 'textAreaNotes';
			}

			if ($render_as_ref) {
				/* a provider-backed secret field holds a non-sensitive reference
				 * (a path/locator) the provider resolves, so it is shown in clear
				 * and editable like any other field */
				$field['friendly_name'] = $f['friendly_name'] . ' ' . ($provider_driver !== null ? '(' . $provider_driver->referenceLabel() . ')' : __('(reference)', 'credentials')) . (!empty($f['required']) ? ' *' : '');
				$field['value']         = isset($props[$fname]) ? $props[$fname] : '';

				if ($provider_driver !== null) {
					$field['description'] .= '<br><br>' . $provider_driver->referenceHint();
				}
			} elseif ($is_secret) {
				/* never echo a stored secret back to the browser */
				$field['value'] = '';

				if (credentials_secret_is_set($props, $fname)) {
					$field['description'] .= '<br><br><strong>' . __('A value is currently stored (encrypted).', 'credentials') . '</strong> ' . __('Leave this blank to keep it, or enter a new value to replace it.', 'credentials');
				} else {
					$field['description'] .= '<br><br><em>' . __('No value stored yet.', 'credentials') . '</em>';
				}
			} else {
				$field['value'] = isset($props[$fname]) ? $props[$fname] : (isset($f['default']) ? $f['default'] : '');
			}

			$fields[$fname] = $field;
		}
	}

	$fields['original_type'] = array(
		'method' => 'hidden',
		'value'  => $row['type'],
	);

	$fields['id'] = array(
		'method' => 'hidden_zero',
		'value'  => $row['id'],
	);

	$fields['save_component_credential'] = array(
		'method' => 'hidden',
		'value'  => '1',
	);

	form_start('credentials.php', 'credentials_edit');

	html_start_box($header, '100%', true, '3', 'center', '');

	draw_edit_form(array(
		'config' => array(),
		'fields' => $fields,
	));

	html_end_box(true, true);

	?>
	<script type='text/javascript' <?php print credentials_csp_nonce();?>>
	var credentialsId              = <?php print (int) $row['id'];?>;
	var credentialsOriginalType    = <?php print json_encode($row['type']);?>;
	var credentialsCurrentType     = <?php print json_encode($type);?>;
	var credentialsProviderCurrent = <?php print (int) $provider_id;?>;
	var credentialsStrings      = <?php print json_encode(array(
		'title'    => __('Change Credential Type?', 'credentials'),
		'body'     => __('Changing the Credential Type will discard the values stored for the current type when you save this credential. Do you want to continue?', 'credentials'),
		'continue' => __('Continue', 'credentials'),
		'cancel'   => __('Cancel', 'credentials'),
	), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);?>;

	// Cacti AJAX navigation swaps only #main, so the page_head <script> that
	// loads credentials.js is absent when Credentials is entered from another
	// Console page, and its ready handler never reruns for AJAX-loaded Add/Edit
	// fragments. Load the script when needed and (re)initialize the form-scoped
	// handler for this fragment; credentialsInitTypeWarning() is idempotent.
	(function() {
		function init() {
			if (typeof window.credentialsInitTypeWarning === 'function') {
				window.credentialsInitTypeWarning();
			}
		}

		if (typeof window.credentialsInitTypeWarning === 'function') {
			init();
		} else {
			var existing = document.getElementById('credentials-js');

			if (existing) {
				existing.addEventListener('load', init);
			} else {
				var s   = document.createElement('script');
				s.id    = 'credentials-js';
				s.src   = '<?php print $config['url_path'];?>plugins/credentials/credentials.js';
				var cur = document.currentScript;

				if (cur && cur.nonce) {
					s.setAttribute('nonce', cur.nonce);
					s.nonce = cur.nonce;
				}

				s.onload = init;
				document.head.appendChild(s);
			}
		}
	})();
	</script>
	<?php

	form_save_button('credentials.php', 'return', 'id');
}
