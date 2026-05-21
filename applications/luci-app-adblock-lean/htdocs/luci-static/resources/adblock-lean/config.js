'use strict';
'require fs';
'require adblock-lean.hagezi as hagezi';
'require adblock-lean.helpers as helpers';
'require adblock-lean.rpc as rpc';

return L.Class.extend({
	checkConfigResult: null,
	data: { 'config': null },
	hasSupportedConfigFormat: false,
	loaded: false,
	rawConfig: null,
	resetNeeded: false,
	supportedConfigFormat: 11,
	updateNeeded: false,

	load: async function () {
		try {
			this.rawConfig = await fs.read_direct('/etc/adblock-lean/config');
			if (this.rawConfig) {
				this.loaded = true;

				// Parse the config file format, converting the key=value lines into an object
				// From: https://stackoverflow.com/a/52043870
				var result = this.rawConfig
					// split the data by line
					.split('\n')
					// filter comments
					.filter(row => (row.trim() != '') && !row.trim().startsWith('#') && (row.indexOf('=') > 0))
					// split each row into key and property
					.map(row => {
						var equalsPos = row.indexOf('=');
						var key = row.substring(0, equalsPos);
						var value = row.substring(equalsPos + 1);
						return [key.trim(), helpers.getCleanValue(value)];
					})
					// use reduce to assign key-value pairs to a new object
					// using Array.prototype.reduce
					.reduce((acc, [key, value]) => (acc[key] = value, acc), {});
		
				// *_lists need to be an array, not a space-separated string
				// v11 key names (preferred)
				result.raw_block_lists = result.raw_block_lists ? result.raw_block_lists.split(' ') : [];
				result.raw_allow_lists = result.raw_allow_lists ? result.raw_allow_lists.split(' ') : [];
				result.raw_ipv4_block_lists = result.raw_ipv4_block_lists ? result.raw_ipv4_block_lists.split(' ') : [];
				result.dnsmasq_block_lists = result.dnsmasq_block_lists ? result.dnsmasq_block_lists.split(' ') : [];
				result.dnsmasq_ipv4_block_lists = result.dnsmasq_ipv4_block_lists ? result.dnsmasq_ipv4_block_lists.split(' ') : [];
				result.dnsmasq_allow_lists = result.dnsmasq_allow_lists ? result.dnsmasq_allow_lists.split(' ') : [];
				result.hosts_block_lists = result.hosts_block_lists ? result.hosts_block_lists.split(' ') : [];

				// v10 legacy key names (fallback if v11 keys are empty)
				var legacy_blocklist_urls = result.blocklist_urls ? result.blocklist_urls.split(' ') : [];
				var legacy_blocklist_ipv4_urls = result.blocklist_ipv4_urls ? result.blocklist_ipv4_urls.split(' ') : [];
				var legacy_allowlist_urls = result.allowlist_urls ? result.allowlist_urls.split(' ') : [];
				var legacy_dnsmasq_blocklist_urls = result.dnsmasq_blocklist_urls ? result.dnsmasq_blocklist_urls.split(' ') : [];
				var legacy_dnsmasq_blocklist_ipv4_urls = result.dnsmasq_blocklist_ipv4_urls ? result.dnsmasq_blocklist_ipv4_urls.split(' ') : [];
				var legacy_dnsmasq_allowlist_urls = result.dnsmasq_allowlist_urls ? result.dnsmasq_allowlist_urls.split(' ') : [];

				if (result.raw_block_lists.length === 0 && legacy_blocklist_urls.length > 0) result.raw_block_lists = legacy_blocklist_urls;
				if (result.raw_allow_lists.length === 0 && legacy_allowlist_urls.length > 0) result.raw_allow_lists = legacy_allowlist_urls;
				if (result.raw_ipv4_block_lists.length === 0 && legacy_blocklist_ipv4_urls.length > 0) result.raw_ipv4_block_lists = legacy_blocklist_ipv4_urls;
				if (result.dnsmasq_block_lists.length === 0 && legacy_dnsmasq_blocklist_urls.length > 0) result.dnsmasq_block_lists = legacy_dnsmasq_blocklist_urls;
				if (result.dnsmasq_ipv4_block_lists.length === 0 && legacy_dnsmasq_blocklist_ipv4_urls.length > 0) result.dnsmasq_ipv4_block_lists = legacy_dnsmasq_blocklist_ipv4_urls;
				if (result.dnsmasq_allow_lists.length === 0 && legacy_dnsmasq_allowlist_urls.length > 0) result.dnsmasq_allow_lists = legacy_dnsmasq_allowlist_urls;

				// v10 legacy: min_blocklist_ipv4_part_line_count → min_ipv4_blocklist_part_line_count
				if (!result.min_ipv4_blocklist_part_line_count && result.min_blocklist_ipv4_part_line_count) {
					result.min_ipv4_blocklist_part_line_count = result.min_blocklist_ipv4_part_line_count;
				}

				// We have a friendly Hagezi Blocklists multi-select, so we need to split those in raw_block_lists into hagezi_blocklists
				result.hagezi_blocklists = [];
				var nonHageziBlocklists = [];
				for (var i = 0; i < result.raw_block_lists.length; i++) {
					if (result.raw_block_lists[i].startsWith(hagezi.baseUrl)) {
						result.hagezi_blocklists.push(result.raw_block_lists[i]);
					} else {
						nonHageziBlocklists.push(result.raw_block_lists[i]);
					}
				}
				result.raw_block_lists = nonHageziBlocklists;
			
				// custom_script needs to be mapped to enable_custom_script
				if (result.custom_script) {
					result.enable_custom_script = 1;
				}

				// Set the data variable in the format needed by form.JSONMap()
				this.data.config = result;

				// Set the hasSupportedConfigFormat flag
				this.hasSupportedConfigFormat = (this.rawConfig.indexOf('config_format=v' + this.supportedConfigFormat) >= 0)

				// Call the checkConfig RPC method to see if an update/reset is needed
				this.checkConfigResult = await rpc.checkConfig();
				switch (parseInt(this.checkConfigResult.config_status)) {
					case 0: break; // Config file is OK, so do nothing
					case 1: this.resetNeeded = true; break;
					case 2: this.updateNeeded = true; break;
					default: throw new Error(_('Error validating config file: %s returned an unexpected value (%s)').format('parse_config', this.checkConfigResult.config_status));
				}
			}
		} catch (e) {
			// Failed to read the file.  If it's NOT a NotFoundError, throw to report the error
			if (e.name !== 'NotFoundError') {
				throw e;
			}
		}
	},

	save: async function() {
		var data = this.data.config;

		// Marge the hagezi blocklist and other blocklist selections into one array
		var combined_blocklist_urls = [];
		if (data.hagezi_blocklists) {
			for (var i = 0; i < data.hagezi_blocklists.length; i++) {
				combined_blocklist_urls.push(data.hagezi_blocklists[i]);
			}
		}
		if (data.raw_block_lists) {
			for (var i = 0; i < data.raw_block_lists.length; i++) {
				combined_blocklist_urls.push(data.raw_block_lists[i]);
			}
		}

		// Abort if user did not select or enter at least one blocklist
		if (combined_blocklist_urls.length == 0) {
			throw new Error(_('Must select or provide at least one blocklist'));
		}

		// enable_custom_script needs to be mapped to custom_script
		if (data.enable_custom_script) {
			// User wants to use a custom script, so assign custom_script the default value if it doesn't already have one
			if (!data.custom_script) {
				data.custom_script = '/usr/libexec/abl_custom-script.sh';
			}
		} else {
			// User doesn't want to use a custom script, so clear the custom_script value
			data.custom_script = '';
		}
		
		var config = '\n\
# adblock-lean configuration options\n\
# config_format=v' + this.supportedConfigFormat + '\n\
#\n\
# values must be enclosed in double-quotes\n\
# custom comments are not preserved after automatic config update\n\
\n\
# Whitelist mode: only domains (and their subdomains) included in the allowlist(s) are allowed, all other domains are blocked\n\
# In this mode, if blocklists are used in addition to allowlists, subdomains included in the blocklists will be blocked,\n\
# including subdomains of allowed domains\n\
whitelist_mode="' + data.whitelist_mode + '"\n\
\n\
# One or more *raw domain* format blocklist/ipv4 blocklist/allowlist URLs and/or short list identifiers separated by spaces\n\
raw_block_lists="' + combined_blocklist_urls.join(' ') + '"\n\
raw_allow_lists="' + (data.raw_allow_lists ?? []).join(' ') + '"\n\
raw_ipv4_block_lists="' + (data.raw_ipv4_block_lists ?? []).join(' ') + '"\n\
\n\
# One or more *dnsmasq* format domain blocklist/ipv4 blocklist/allowlist URLs separated by spaces\n\
dnsmasq_block_lists="' + (data.dnsmasq_block_lists ?? []).join(' ') + '"\n\
dnsmasq_ipv4_block_lists="' + (data.dnsmasq_ipv4_block_lists ?? []).join(' ') + '"\n\
dnsmasq_allow_lists="' + (data.dnsmasq_allow_lists ?? []).join(' ') + '"\n\
\n\
# One or more *hosts* format blocklist URLs and/or short list identifiers separated by spaces\n\
hosts_block_lists="' + (data.hosts_block_lists ?? []).join(' ') + '"\n\
\n\
# Path to optional local *raw domain* allowlist/blocklist files in the form:\n\
# site1.com\n\
# site2.com\n\
local_allowlist_path="' + data.local_allowlist_path + '"\n\
local_blocklist_path="' + data.local_blocklist_path + '"\n\
\n\
# Test domains are automatically querried after loading the blocklist into dnsmasq,\n\
# in order to verify that the blocklist didn\'t break DNS resolution\n\
# If query for any of the test domains fails, previous blocklist is restored from backup\n\
# If backup doesn\'t exist, the blocklist is removed and adblock-lean is stopped\n\
# Leaving this empty will disable verification\n\
test_domains="' + data.test_domains + '"\n\
\n\
# List part failed action:\n\
# This option applies to blocklist/allowlist parts which failed to download or couldn\'t pass validation checks\n\
# SKIP - skip failed blocklist file part and continue blocklist generation\n\
# STOP - stop blocklist generation (and fall back to previous blocklist if available)\n\
list_part_failed_action="' + data.list_part_failed_action + '"\n\
\n\
# Maximum number of download retries\n\
max_download_retries="' + data.max_download_retries + '"\n\
\n\
# Default download mirrors.\n\
# Hagezi mirror: \'github\' or \'gitlab\'\n\
hagezi_default_mirror="' + (data.hagezi_default_mirror || 'github') + '"\n\
# oisd mirror: \'oisd\' or \'github\'\n\
oisd_default_mirror="' + (data.oisd_default_mirror || 'oisd') + '"\n\
# Steven Black mirror: \'github\' or \'sbc_io\' for sbc.io\n\
stevenblack_default_mirror="' + (data.stevenblack_default_mirror || 'github') + '"\n\
\n\
# Minimum number of good lines in final postprocessed blocklist\n\
min_good_line_count="' + data.min_good_line_count + '"\n\
\n\
# Mininum number of lines of any individual downloaded part\n\
min_blocklist_part_line_count="' + data.min_blocklist_part_line_count + '"\n\
min_ipv4_blocklist_part_line_count="' + data.min_ipv4_blocklist_part_line_count + '"\n\
min_allowlist_part_line_count="' + data.min_allowlist_part_line_count + '"\n\
\n\
# Maximum size of any individual downloaded blocklist part\n\
max_file_part_size_KB="' + data.max_file_part_size_KB + '"\n\
\n\
# Maximum total size of combined, processed blocklist\n\
max_blocklist_file_size_KB="' + data.max_blocklist_file_size_KB + '"\n\
\n\
# Whether to perform sorting and deduplication of entries (usually doesn\'t cause much slowdown, uses a bit more memory) - enable (1) or disable (0)\n\
deduplication="' + ((data.deduplication ?? false) ? '1' : '0') + '"\n\
\n\
# Utility to compress final blocklist, intermediate blocklist parts and the backup blocklist to save memory\n\
# Supported options: gzip, pigz, zstd or \'none\' to disable compression\n\
compression_util="' + data.compression_util + '"\n\
\n\
# Compression options: passed as-is to the compression utility\n\
# Available options depend on the compression utility. \'-[n]\' universally specifies compression level.\n\
# Busybox gzip ignores any options.\n\
#   Intermediate compression. Default: \'-3\'.\n\
intermediate_compression_options="' + data.intermediate_compression_options + '"\n\
#   Final blocklist compression. Default: \'-6\'\n\
final_compression_options="' + data.final_compression_options + '"\n\
\n\
# unload previous blocklist form memory and restart dnsmasq before generation of\n\
# new blocklist in order to free up memory during generation of new blocklist - \'auto\' or enable (1) or disable (0)\n\
unload_blocklist_before_update="' + data.unload_blocklist_before_update + '"\n\
\n\
# Start delay in seconds when service is started from system boot\n\
boot_start_delay_s="' + data.boot_start_delay_s + '"\n\
\n\
# Maximal count of download and processing jobs run in parallel. \'auto\' sets this value to the count of CPU cores\n\
MAX_PARALLEL_JOBS="' + data.MAX_PARALLEL_JOBS + '"\n\
\n\
# If a path to custom script is specified and that script defines functions\n\
# \'report_success()\', \'report_failure()\' or \'report_update()\',\n\
# one of these functions will be executed when adblock-lean completes the execution of some commands,\n\
# with corresponding message passed in first argument\n\
# report_success() and report_update() are only executed upon completion of the \'start\' command\n\
# Recommended path is \'/usr/libexec/abl_custom-script.sh\' which the luci app has permission to access\n\
custom_script="' + data.custom_script + '"\n\
\n\
# Crontab schedule expression for periodic list updates\n\
cron_schedule="' + data.cron_schedule + '"\n\
\n\
# dnsmasq instance indexes and config directories\n\
# normally this should be set automatically by the \'setup\' command\n\
DNSMASQ_INDEXES="' + data.DNSMASQ_INDEXES + '"\n\
DNSMASQ_CONF_DIRS="' + data.DNSMASQ_CONF_DIRS + '"\n';

		// Save config file
		await fs.write('/etc/adblock-lean/config', config);
	
		// Check if we should save the starter custom script.  We only do this if custom_script is set
		// to the default path, which we have read/write access to
		if (data.custom_script == '/usr/libexec/abl_custom-script.sh') {
			try {
				// Try to stat the file.  If we get a result that means the file already exists so we'll return
				var statResult = await fs.stat('/usr/libexec/abl_custom-script.sh');
				if (L.isObject(statResult)) {
					return;
				}
			} catch (e) {
				// Failed to stat the file.  If it's NOT a NotFoundError, throw to report the error
				if (e.name !== 'NotFoundError') {
					throw e;
				}
			}
					
			// If we get here the file was not found, so we can write a new one
			await fs.write('/usr/libexec/abl_custom-script.sh', '#!/bin/sh\n\
\n\
report_failure()\n\
{\n\
mailbody="${1}"\n\
\n\
# Example to send an email\n\
# mailsend -port 587 -smtp smtp-relay.brevo.com -auth -f FROM@EMAIL.COM -t TO@EMAIL.COM -user BREVO@USERNAME.COM -pass PASSWORD -sub "adblock-lean blocklist update failed" -M "${mailbody}"\n\
\n\
# Example to request an http(s) url:\n\
# uclient-fetch -q -O - --post-data="${mailbody}" https://hc-ping.com/<uuid>/fail\n\
}\n\
\n\
report_success()\n\
{\n\
mailbody="${1}"\n\
\n\
# Example to send an email:\n\
# mailsend -port 587 -smtp smtp-relay.brevo.com -auth -f FROM@EMAIL.COM -t TO@EMAIL.COM -user BREVO@USERNAME.COM -pass PASSWORD -sub "adblock-lean blocklist update success" -M "${mailbody}"\n\
\n\
# Example to request an http(s) url:\n\
# uclient-fetch -q -O - --post-data="${mailbody}" https://hc-ping.com/<uuid>\n\
}\n');
		}
	}
});