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

// Reload a Console page/fragment via AJAX, compatible across Cacti releases.
// Cacti 1.3+/develop expose loadUrl(); the 1.2.x line (the plugin's declared
// compat floor) only has loadPageNoHeader(). Define this once as a global so
// every page -- including those reached through AJAX navigation where this file
// may not be reloaded -- can reuse it; the inline scripts emit an identical
// guarded fallback for the case where this file is not present.
window.credentialsLoadUrl = window.credentialsLoadUrl || function(url, force) {
	if (typeof loadUrl === 'function') {
		loadUrl({ url: url, force: force === true });
	} else if (typeof loadPageNoHeader === 'function') {
		// request an AJAX fragment; append header=false only when absent
		var href = url + (url.indexOf('header=') === -1 ? ((url.indexOf('?') === -1 ? '?' : '&') + 'header=false') : '');
		loadPageNoHeader(href, false, force === true);
	} else {
		document.location = url;
	}
};

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

		if (typeof credentialsProviderCurrent !== 'undefined') {
			url += '&provider_id=' + encodeURIComponent(credentialsProviderCurrent);
		}

		// reload the edit form in place via an AJAX callback instead of a full
		// page navigation; force past the unsaved-changes check because the type
		// switch intentionally rebuilds the form
		credentialsLoadUrl(url, true);
	}

	// Switching the backing Secret Provider re-renders the type-specific fields
	// (masked local secrets vs. plain provider references), so reload the edit
	// form for the newly selected provider, preserving the current type and id.
	var providerSelect = $('#provider_id');

	if (providerSelect.length) {
		providerSelect.off('change.credprovider').on('change.credprovider', function() {
			var id    = (typeof credentialsId !== 'undefined') ? credentialsId : 0;
			var type  = (typeof credentialsCurrentType !== 'undefined') ? credentialsCurrentType : $('#type').val();
			var url   = 'credentials.php?action=edit&type=' + encodeURIComponent(type) + '&provider_id=' + encodeURIComponent($(this).val());

			if (id > 0) {
				url += '&id=' + id;
			}

			// AJAX callback reload (see reloadForType) rather than a full refresh
			credentialsLoadUrl(url, true);
		});
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
