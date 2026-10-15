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
	case 'ajax_test':
		provider_ajax_test();

		break;
	case 'edit':
		top_header();

		provider_edit();

		bottom_footer();

		break;
	default:
		top_header();

		provider_list();

		bottom_footer();

		break;
}

/**
 * Persist a provider instance from the edit form. Secret configuration fields
 * (tokens, keys, client secrets) are encrypted with the Cacti core secret
 * functions; a blank secret on an existing provider keeps the previously stored
 * value. Switching the provider type replaces the type-specific configuration
 * entirely (the user is warned client-side first).
 *
 * @return void
 */
function form_save(): void {
	if (!isset_request_var('save_component_provider')) {
		header('Location: credential_providers.php');

		exit;
	}

	get_filter_request_var('id');

	$id   = get_nfilter_request_var('id');
	$type = get_nfilter_request_var('type');

	$driver = credentials_provider_driver($type);

	if ($driver === null) {
		raise_message('prov_badtype', __('The selected provider type is not valid.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : ''));

		exit;
	}

	$name = trim(get_nfilter_request_var('name'));

	if ($name == '') {
		raise_message('prov_noname', __('A provider name is required.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

		exit;
	}

	$config_fields = $driver->configFields();

	/* previous row + properties, used to preserve unchanged secrets */
	$prev_props = array();
	$prev_type  = '';

	if (!empty($id)) {
		$existing = db_fetch_row_prepared('SELECT * FROM credential_providers WHERE id = ?', array($id));

		if (is_array($existing) && cacti_sizeof($existing)) {
			$prev_type = $existing['type'];

			if ($prev_type == $type) {
				$prev_props = credentials_provider_properties($existing);
			}
		}
	}

	/* if any secret is being set and core encryption is unavailable, fail closed */
	$needs_encryption = false;

	foreach ($config_fields as $fname => $field) {
		if (!empty($field['secret']) && (isset_request_var($fname) ? get_nfilter_request_var($fname) : '') !== '') {
			$needs_encryption = true;
		}
	}

	if ($needs_encryption && !credentials_encryption_available()) {
		raise_message('prov_noenc', __('Cannot store a secret: the Cacti core secret encryption functions are unavailable on this installation.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

		exit;
	}

	$props = array();

	foreach ($config_fields as $fname => $field) {
		if (!empty($field['secret'])) {
			$posted = isset_request_var($fname) ? get_nfilter_request_var($fname) : '';

			if ($posted === '') {
				if (isset($prev_props[$fname]) && $prev_props[$fname] !== '') {
					$props[$fname] = $prev_props[$fname];
				} elseif (!empty($field['required'])) {
					raise_message('prov_req_' . $fname, __('\'%s\' is required.', $field['friendly_name'], 'credentials'), MESSAGE_LEVEL_ERROR);
					header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

					exit;
				}
			} else {
				list($enc_ok, $enc_val) = credentials_try_encrypt($posted);

				if (!$enc_ok) {
					raise_message('prov_encfail', __('Could not encrypt the secret. Verify the Cacti encryption key configuration and try again.', 'credentials'), MESSAGE_LEVEL_ERROR);
					header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

					exit;
				}

				$props[$fname] = $enc_val;
			}
		} else {
			$value = isset_request_var($fname) ? get_nfilter_request_var($fname) : '';

			if ($field['method'] == 'drop_array' && isset($field['array']) && !array_key_exists($value, $field['array'])) {
				$value = isset($field['default']) ? $field['default'] : '';
			}

			if ($value === '' && !empty($field['required'])) {
				raise_message('prov_req_' . $fname, __('\'%s\' is required.', $field['friendly_name'], 'credentials'), MESSAGE_LEVEL_ERROR);
				header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

				exit;
			}

			$props[$fname] = $value;
		}
	}

	$encoded_props = json_encode($props);

	if ($encoded_props === false) {
		raise_message('prov_encode', __('The provider could not be saved because one of its fields contains invalid characters. Please re-enter the affected values and try again.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);

		exit;
	}

	$save                = array();
	$save['id']          = $id;
	$save['name']        = $name;
	$save['description'] = get_nfilter_request_var('description');
	$save['type']        = $type;
	$save['enabled']     = isset_request_var('enabled') ? 'on' : '';
	$save['properties']  = $encoded_props;

	$new_id = sql_save($save, 'credential_providers');

	if ($new_id) {
		raise_message('prov_saved', __('Secret provider saved.', 'credentials'), MESSAGE_LEVEL_INFO);
		header('Location: credential_providers.php?action=edit&id=' . $new_id);
	} else {
		raise_message('prov_savefail', __('Failed to save the secret provider.', 'credentials'), MESSAGE_LEVEL_ERROR);
		header('Location: credential_providers.php?action=edit' . ($id > 0 ? '&id=' . $id : '') . '&type=' . $type);
	}

	exit;
}

/**
 * Process the bulk action form (delete / enable / disable). A provider that is
 * still referenced by one or more credentials is not deleted, so credentials
 * never silently lose their secret source.
 *
 * @return void
 */
function form_actions(): void {
	global $actions;

	/* bulk actions are state-changing: require POST so the request carries
	 * Cacti's CSRF token and cannot be triggered through a crafted GET */
	if (!isset($_SERVER['REQUEST_METHOD']) || strtoupper($_SERVER['REQUEST_METHOD']) !== 'POST') {
		header('Location: credential_providers.php');

		exit;
	}

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items != false) {
			$action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				$id = intval($id);

				if ($action == '1') {
					$in_use = db_fetch_cell_prepared('SELECT COUNT(*) FROM credentials WHERE provider_id = ?', array($id));

					if ($in_use > 0) {
						raise_message('prov_inuse_' . $id, __('A provider still used by %d credential(s) was not deleted.', $in_use, 'credentials'), MESSAGE_LEVEL_WARN);
					} else {
						db_execute_prepared('DELETE FROM credential_providers WHERE id = ?', array($id));
					}
				} elseif ($action == '2') {
					db_execute_prepared('UPDATE credential_providers SET enabled = \'on\' WHERE id = ?', array($id));
				} elseif ($action == '3') {
					db_execute_prepared('UPDATE credential_providers SET enabled = \'\' WHERE id = ?', array($id));
				}
			}
		}

		header('Location: credential_providers.php');

		exit;
	}

	$ids = array();

	foreach (array_keys($_POST) as $var) {
		if (preg_match('/^chk_([0-9]+)$/', $var, $matches)) {
			input_validate_input_number($matches[1], 'chk_id');
			$ids[] = (int) $matches[1];
		}
	}

	$drp_action = get_nfilter_request_var('drp_action');

	if (!isset($actions[$drp_action])) {
		header('Location: credential_providers.php');

		exit;
	}

	top_header();

	form_start('credential_providers.php');

	html_start_box($actions[$drp_action], '60%', '', '3', 'center', '');

	$items = '';

	if (cacti_sizeof($ids)) {
		$placeholders = implode(',', array_fill(0, cacti_sizeof($ids), '?'));
		$names        = db_fetch_assoc_prepared("SELECT id, name FROM credential_providers WHERE id IN ($placeholders) ORDER BY name", $ids);

		foreach ($names as $row) {
			$items .= '<li>' . html_escape($row['name']) . '</li>';
		}
	}

	if ($drp_action == '1') {
		$title = __('Delete the following secret provider(s)?', 'credentials');
	} elseif ($drp_action == '2') {
		$title = __('Enable the following secret provider(s)?', 'credentials');
	} else {
		$title = __('Disable the following secret provider(s)?', 'credentials');
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
			<input type='hidden' name='selected_items' value='" . html_escape(serialize($ids)) . "'>
			<input type='hidden' name='drp_action' value='" . html_escape($drp_action) . "'>
			$save_html
		</td>
	</tr>";

	html_end_box();

	form_end();

	bottom_footer();
}

/**
 * AJAX endpoint: run a saved provider's connectivity/auth self-test and return
 * the outcome as JSON. State-reading but network-touching, so it requires POST
 * (carrying Cacti's CSRF token) and the Users/Groups realm asserted above.
 *
 * @return void
 */
function provider_ajax_test(): void {
	header('Content-Type: application/json; charset=utf-8');

	if (!isset($_SERVER['REQUEST_METHOD']) || strtoupper($_SERVER['REQUEST_METHOD']) !== 'POST') {
		print json_encode(array('ok' => false, 'message' => __('Invalid request method.', 'credentials')));

		exit;
	}

	get_filter_request_var('id');

	$id = (int) get_request_var('id');

	if ($id <= 0) {
		print json_encode(array('ok' => false, 'message' => __('Save the provider before testing it.', 'credentials')));

		exit;
	}

	list($ok, $message) = credentials_provider_test($id);

	print json_encode(array('ok' => (bool) $ok, 'message' => $message));

	exit;
}

/**
 * Render the provider management list.
 *
 * @return void
 */
function provider_list(): void {
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

	validate_store_request_vars($filters, 'sess_credprov');

	$allowed_sort = array(
		'name'         => 'name',
		'type'         => 'type',
		'description'  => 'description',
		'enabled'      => 'enabled',
		'last_updated' => 'last_updated',
	);

	$sort_key    = get_request_var('sort_column');
	$sort_column = isset($allowed_sort[$sort_key]) ? $allowed_sort[$sort_key] : 'name';
	$sort_dir    = (strtoupper(get_request_var('sort_direction')) == 'DESC') ? 'DESC' : 'ASC';

	$sql_where = '';
	$params    = array();

	if (get_request_var('filter') != '') {
		$sql_where = 'WHERE (name LIKE ? OR description LIKE ?)';
		$params[]  = '%' . get_request_var('filter') . '%';
		$params[]  = '%' . get_request_var('filter') . '%';
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*) FROM credential_providers $sql_where", $params);

	$rows_per_page = get_request_var('rows');

	if ($rows_per_page == -1) {
		$rows_per_page = $total_rows;
	}

	$rows_per_page = max(1, (int) $rows_per_page);
	$page          = max(1, (int) get_request_var('page'));
	$sql_limit     = ' LIMIT ' . ($rows_per_page * ($page - 1)) . ',' . $rows_per_page;

	$providers = db_fetch_assoc_prepared("SELECT *
		FROM credential_providers
		$sql_where
		ORDER BY $sort_column $sort_dir
		$sql_limit", $params);

	$type_labels = credentials_provider_type_options();

	?>
	<script type='text/javascript' <?php print credentials_csp_nonce();?>>
	function applyFilter() {
		strURL  = 'credential_providers.php?header=false';
		strURL += '&filter=' + encodeURIComponent($('#filter').val());
		strURL += '&rows='   + encodeURIComponent($('#rows').val());
		strURL += '&page=1';
		loadPageNoHeader(strURL);
	}

	function clearFilter() {
		strURL = 'credential_providers.php?clear=true&header=false';
		loadPageNoHeader(strURL);
	}

	$(function() {
		$('#refresh').click(function() { applyFilter(); });
		$('#clear').click(function() { clearFilter(); });
		$('#form_providers').submit(function(event) {
			event.preventDefault();
			applyFilter();
		});
	});
	</script>
	<?php

	html_start_box(__('Secret Providers', 'credentials'), '100%', '', '3', 'center', 'credential_providers.php?action=edit');

	?>
	<tr class='even noprint'>
		<td>
		<form id='form_providers' action='credential_providers.php' method='get'>
			<table class='filterTable'>
				<tr>
					<td><?php print __('Search', 'credentials');?></td>
					<td>
						<input type='text' class='ui-state-default ui-corner-all' id='filter' size='30' value='<?php print html_escape(get_request_var('filter'));?>'>
					</td>
					<td><?php print __('Providers', 'credentials');?></td>
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

	$nav = html_nav_bar('credential_providers.php', MAX_DISPLAY_PAGES, $page, $rows_per_page, $total_rows, 6, __('Secret Providers', 'credentials'), 'page', 'main');

	print $nav;

	form_start('credential_providers.php', 'chk');

	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'name'         => array('display' => __('Name', 'credentials'),         'sort' => 'ASC', 'align' => 'left'),
		'type'         => array('display' => __('Type', 'credentials'),         'sort' => 'ASC', 'align' => 'left'),
		'description'  => array('display' => __('Description', 'credentials'),   'sort' => 'ASC', 'align' => 'left', 'nohide' => true),
		'enabled'      => array('display' => __('Enabled', 'credentials'),      'sort' => 'ASC', 'align' => 'left'),
		'last_updated' => array('display' => __('Last Updated', 'credentials'), 'sort' => 'DESC', 'align' => 'left'),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	if (cacti_sizeof($providers)) {
		foreach ($providers as $row) {
			$type_name = isset($type_labels[$row['type']]) ? $type_labels[$row['type']] : $row['type'];

			form_alternate_row('line' . $row['id'], true);

			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('credential_providers.php?action=edit&id=' . $row['id']) . '">' . html_escape($row['name']) . '</a>', $row['id']);
			form_selectable_cell(html_escape($type_name), $row['id']);
			form_selectable_cell(html_escape($row['description']), $row['id']);
			form_selectable_cell($row['enabled'] == 'on' ? __('Yes', 'credentials') : __('No', 'credentials'), $row['id']);
			form_selectable_cell(html_escape($row['last_updated']), $row['id']);
			form_checkbox_cell($row['name'], $row['id']);

			form_end_row();
		}
	} else {
		print "<tr class='tableRow odd'><td colspan='6'><em>" . __('No Secret Providers Found', 'credentials') . '</em></td></tr>';
	}

	html_end_box(false);

	if (cacti_sizeof($providers)) {
		print $nav;
	}

	draw_actions_dropdown($actions);

	form_end();
}

/**
 * Render the add/edit form for a single provider instance. Base fields (name,
 * description, type, enabled) are followed by the fields specific to the
 * selected provider type; secret fields are rendered masked.
 *
 * @return void
 */
function provider_edit(): void {
	global $config;

	get_filter_request_var('id');

	$id  = isempty_request_var('id') ? 0 : get_request_var('id');
	$row = array('id' => 0, 'name' => '', 'description' => '', 'type' => '', 'enabled' => 'on');

	if (!empty($id)) {
		$fetched = db_fetch_row_prepared('SELECT * FROM credential_providers WHERE id = ?', array($id));

		if (is_array($fetched) && cacti_sizeof($fetched)) {
			$row = $fetched;
		} else {
			$id = 0;
		}
	}

	$props   = credentials_provider_properties($row);
	$options = credentials_provider_type_options();

	if (isset_request_var('type') && credentials_provider_driver(get_nfilter_request_var('type')) !== null) {
		$type = get_nfilter_request_var('type');
	} elseif ($row['type'] != '' && credentials_provider_driver($row['type']) !== null) {
		$type = $row['type'];
	} else {
		$type = key($options);
	}

	if ($type != $row['type']) {
		$props = array();
	}

	$driver = credentials_provider_driver($type);

	$header = ($id > 0) ? __esc('Secret Provider [edit: %s]', $row['name'], 'credentials') : __('Secret Provider [new]', 'credentials');

	$fields = array(
		'name' => array(
			'method'        => 'textbox',
			'friendly_name' => __('Name', 'credentials'),
			'description'   => __('A unique, meaningful name for this provider instance.', 'credentials'),
			'value'         => $row['name'],
			'max_length'    => 128,
			'size'          => 60,
		),
		'description' => array(
			'method'        => 'textbox',
			'friendly_name' => __('Description', 'credentials'),
			'description'   => __('An optional description of this provider instance.', 'credentials'),
			'value'         => $row['description'],
			'max_length'    => 255,
			'size'          => 60,
		),
		'type' => array(
			'method'        => 'drop_array',
			'friendly_name' => __('Provider Type', 'credentials'),
			'description'   => __('The external secret store this provider connects to. Changing the type on an existing provider discards the previously stored type-specific configuration when you save.', 'credentials'),
			'value'         => $type,
			'array'         => $options,
		),
		'enabled' => array(
			'method'        => 'checkbox',
			'friendly_name' => __('Enabled', 'credentials'),
			'description'   => __('Whether this provider is available to resolve credential secrets.', 'credentials'),
			'value'         => $row['enabled'],
			'default'       => 'on',
			'form_id'       => $id,
		),
	);

	if ($driver !== null) {
		if ($driver->description() !== '') {
			$fields['type']['description'] .= '<br><br><em>' . $driver->description() . '</em>';
		}

		foreach ($driver->configFields() as $fname => $f) {
			$field = array(
				'friendly_name' => $f['friendly_name'] . (!empty($f['required']) ? ' *' : ''),
				'method'        => $f['method'],
				'description'   => $f['description'],
			);

			if ($f['method'] == 'drop_array') {
				$field['array'] = $f['array'];

				if (isset($f['default'])) {
					$field['default'] = $f['default'];
				}
			}

			if ($f['method'] == 'checkbox') {
				$field['default'] = isset($f['default']) ? $f['default'] : '';
				$field['form_id'] = $id;
			}

			if ($f['method'] == 'textbox' || $f['method'] == 'textbox_password') {
				$field['max_length'] = isset($f['max_length']) ? $f['max_length'] : 255;
				$field['size']       = 60;
			}

			if ($f['method'] == 'textarea') {
				$field['textarea_rows'] = !empty($f['long']) ? 8 : 4;
				$field['textarea_cols'] = 60;
				$field['class']         = 'textAreaNotes';
			}

			if (!empty($f['secret'])) {
				/* never echo a stored secret back to the browser */
				$field['value'] = '';

				if (credentials_secret_is_set($props, $fname)) {
					$field['description'] .= '<br><br><strong>' . __('A value is currently stored (encrypted).', 'credentials') . '</strong> ' . __('Leave this blank to keep it, or enter a new value to replace it.', 'credentials');
				} else {
					$field['description'] .= '<br><br><em>' . __('No value stored yet.', 'credentials') . '</em>';
				}
			} elseif ($f['method'] == 'checkbox') {
				$field['value'] = isset($props[$fname]) ? $props[$fname] : (isset($f['default']) ? $f['default'] : '');
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

	$fields['save_component_provider'] = array(
		'method' => 'hidden',
		'value'  => '1',
	);

	form_start('credential_providers.php', 'provider_edit');

	html_start_box($header, '100%', true, '3', 'center', '');

	draw_edit_form(array(
		'config' => array(),
		'fields' => $fields,
	));

	html_end_box(true, true);

	if ($id > 0) {
		?>
		<div style='margin:8px 0;'>
			<input type='button' class='ui-button ui-corner-all ui-widget' id='provider_test' value='<?php print __esc('Test Connection', 'credentials');?>'>
			<span id='provider_test_result' style='margin-left:10px;'></span>
		</div>
		<?php
	}

	?>
	<script type='text/javascript' <?php print credentials_csp_nonce();?>>
	var providerId           = <?php print (int) $row['id'];?>;
	var providerOriginalType = <?php print json_encode($row['type']);?>;
	var providerStrings      = <?php print json_encode(array(
		'title'    => __('Change Provider Type?', 'credentials'),
		'body'     => __('Changing the Provider Type will discard the configuration stored for the current type when you save this provider. Do you want to continue?', 'credentials'),
		'continue' => __('Continue', 'credentials'),
		'cancel'   => __('Cancel', 'credentials'),
		'testing'  => __('Testing...', 'credentials'),
		'failed'   => __('The test request failed.', 'credentials'),
	), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);?>;

	(function() {
		function initProviderForm() {
			var typeSelect = $('#type');

			if (typeSelect.length) {
				var lastType = typeSelect.val();

				function reloadForType(newType) {
					var url = 'credential_providers.php?action=edit&type=' + encodeURIComponent(newType);

					if (providerId > 0) {
						url += '&id=' + providerId;
					}

					document.location = url;
				}

				typeSelect.off('change.provider').on('change.provider', function() {
					var newType = $(this).val();

					if (newType === lastType) {
						return;
					}

					if (providerId > 0 && newType !== providerOriginalType) {
						var $dlg = $('<div></div>').attr('title', providerStrings.title).html('<p>' + providerStrings.body + '</p>');

						$dlg.dialog({
							modal: true,
							width: 480,
							resizable: false,
							close: function() {
								typeSelect.val(lastType).trigger('change.select2');
								$(this).remove();
							},
							buttons: [
								{
									text: providerStrings['continue'],
									class: 'ui-button ui-corner-all ui-widget',
									click: function() { lastType = newType; $(this).dialog('close'); reloadForType(newType); }
								},
								{
									text: providerStrings.cancel,
									class: 'ui-button ui-corner-all ui-widget',
									click: function() { $(this).dialog('close'); }
								}
							]
						});
					} else {
						lastType = newType;
						reloadForType(newType);
					}
				});
			}

			$('#provider_test').off('click.provider').on('click.provider', function() {
				var $result = $('#provider_test_result');
				$result.css('color', '').text(providerStrings.testing);

				$.ajax({
					url: 'credential_providers.php?action=ajax_test',
					type: 'POST',
					data: { id: providerId, __csrf_magic: (typeof csrfMagicToken !== 'undefined' ? csrfMagicToken : '') },
					dataType: 'json'
				}).done(function(data) {
					if (data && data.ok) {
						$result.css('color', 'green').text('\u2714 ' + data.message);
					} else {
						$result.css('color', 'red').text('\u2718 ' + (data && data.message ? data.message : providerStrings.failed));
					}
				}).fail(function() {
					$result.css('color', 'red').text('\u2718 ' + providerStrings.failed);
				});
			});
		}

		initProviderForm();
	})();
	</script>
	<?php

	form_save_button('credential_providers.php', 'return', 'id');
}
