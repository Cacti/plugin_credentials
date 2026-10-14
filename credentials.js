/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

// Warn, via a jQueryUI dialog, before switching the Credential Type on an
// already-created credential, because saving after the switch replaces the
// stored type-specific values. The credentialsId / credentialsOriginalType
// globals are emitted inline by credentials.php on the edit form.
function credentialsInitTypeWarning() {
	// Invoked on full-page load and from each AJAX-loaded edit-form fragment, so
	// it must be safe to run repeatedly. The #type id exists on both the edit
	// form and the list filter; bind only on the edit form, identified by the
	// edit-only global the page emits.
	if (typeof credentialsOriginalType === 'undefined') {
		return;
	}

	var typeSelect = $('#type');

	if (typeSelect.length === 0) {
		return;
	}

	// the value currently rendered on the form; Cancel/Escape revert to this
	var lastType = typeSelect.val();

	function reloadForType(newType, id) {
		var url = 'credentials.php?action=edit&type=' + encodeURIComponent(newType);

		if (id > 0) {
			url += '&id=' + id;
		}

		document.location = url;
	}

	// Rebind idempotently: this runs for every edit-form fragment, so drop any
	// previous handler before binding to avoid stacking duplicates.
	typeSelect.off('change.credentials').on('change.credentials', function() {
		var newType = $(this).val();

		if (newType === lastType) {
			return;
		}

		var id   = (typeof credentialsId !== 'undefined') ? credentialsId : 0;
		var orig = (typeof credentialsOriginalType !== 'undefined') ? credentialsOriginalType : '';

		// Only warn for an existing credential that is moving away from its
		// stored type. A brand-new credential (id == 0), or one being switched
		// back to its stored type, just re-renders the fields.
		if (id > 0 && newType !== orig) {
			// localized strings are emitted from PHP; fall back to English
			var s = (typeof credentialsStrings !== 'undefined') ? credentialsStrings : {
				title: 'Change Credential Type?',
				body: 'Changing the Credential Type will discard the values stored for the current type when you save this credential. Do you want to continue?',
				'continue': 'Continue',
				cancel: 'Cancel'
			};

			var $dlg = $('<div></div>')
				.attr('title', s.title)
				.html('<p>' + s.body + '</p>');

			$dlg.dialog({
				modal: true,
				width: 480,
				resizable: false,
				close: function() {
					// Escape and the title-bar X also land here; revert the selector
					// to the rendered type so the shown fields and the selection stay
					// consistent. Continue has already advanced lastType, so this is a
					// no-op for it.
					typeSelect.val(lastType).trigger('change.select2');
					$(this).remove();
				},
				buttons: [
					{
						text: s['continue'],
						class: 'ui-button ui-corner-all ui-widget',
						click: function() {
							lastType = newType;
							$(this).dialog('close');
							reloadForType(newType, id);
						}
					},
					{
						text: s.cancel,
						class: 'ui-button ui-corner-all ui-widget',
						click: function() {
							// the dialog close handler reverts the selector
							$(this).dialog('close');
						}
					}
				]
			});
		} else {
			lastType = newType;
			reloadForType(newType, id);
		}
	});
}

$(function() {
	credentialsInitTypeWarning();
});
