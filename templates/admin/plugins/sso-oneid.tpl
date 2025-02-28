<div class="acp-page-container">
	<!-- IMPORT admin/partials/settings/header.tpl -->

	<div class="row m-0">
		<div id="spy-container" class="col-12 px-0 mb-4" tabindex="0">
			<div class="alert alert-info">
				<strong>Quick Start</strong>
				<ol>
					<li>Register new One ID client to get <strong>Client ID</strong> and <strong>Client Secret</strong> from <a target="_blank" href="https://dpc.one.th">https://dpc.one.th <i class="fa fa-external-link"></i></a></li>
					<li>You can set this values in two ways
						<ul>
							<li>Use environment variables
								<ul>
									<li><code>export SSO_ONEID_CLIENT_ID='Client ID'</code></li>
									<li><code>export SSO_ONEID_CLIENT_SECRET='Client Secret'</code></li>
								</ul>
							</li>
							<li>Use form below (this behavior overrides the environment variables)</li>
						</ul>
					</li>
					<li>Save and restart NodeBB via the ACP Dashboard</li>
				</ol>

				<strong>Quick Start</strong>
				<ol>
					<li>sign in as One ID on <code>{config.relative_path}/auth/oneid</code></li>
					<li>Sign in by Shared Token url <code>{config.relative_path}/auth/oneid/sharedtoken?token=</code></li>
				</ol>
			</div>
			<form role="form" class="sso-oneid-settings">
				<div class="mb-4">
					<h5 class="fw-bold tracking-tight settings-header">One ID client</h5>
					<div class="mb-3">
						<label for="app_id">Server</label>
						<input type="text" name="server" title="Server" class="form-control input-lg" placeholder="https://one.th" value="https://one.th">
					</div>
					<div class="mb-3">
						<label for="app_id">Client ID</label>
						<input type="text" name="id" title="Client ID" class="form-control input-lg" placeholder="Client ID">
					</div>
					<div class="mb-3">
						<label for="secret">Secret</label>
						<input type="text" name="secret" title="Client Secret" class="form-control" placeholder="Client Secret">
					</div>
					<div class="mb-3">
						<label for="refcode">RefCode</label>
						<input type="text" name="refcode" title="RefCode" class="form-control" placeholder="RefCode">
					</div>
				</div>

				<div class="mb-4">
					<h5 class="fw-bold tracking-tight settings-header">Associate Businesses</h5>
					<div class="mb-3" data-type="sorted-list" data-sorted-list="businessList" data-item-template="admin/plugins/business-item" data-form-template="admin/plugins/business-form">
						<ul data-type="list" class="list-group mb-2"></ul>
						<button type="button" data-type="add" class="btn btn-info">Add Business</button>
					</div>
				</div>

				<div class="mb-4">
					<h5 class="fw-bold tracking-tight settings-header">Connect to Intranet Web</h5>
					<div class="form-check">
						<input class="form-check-input" data-toggle-target="#intranetApiServer,#intranetApiKey" type="checkbox" id="intranetSyncEnabled" name="intranetSyncEnabled"/>
						<label class="form-check-label">Enable intranet sync</label>
					</div>
					<div class="mb-3">
						<label for="intranetApiServer">API Server</label>
						<input placeholder="API server" type="text" class="form-control" id="intranetApiServer" name="intranetApiServer"/>
					</div>
					<div class="mb-3">
						<label for="intranetApiKey">API Key</label>
						<input placeholder="Private (Secret) API Key here" type="text" class="form-control" id="intranetApiKey" name="intranetApiKey"/>
					</div>
				</div>

				<div class="mb-4">
					<h5 class="fw-bold tracking-tight settings-header">Block One ID account</h5>
					<div class="mb-3" data-type="sorted-list" data-sorted-list="denyAccountList" data-item-template="admin/plugins/deny-account-item" data-form-template="admin/plugins/deny-account-form">
						<ul data-type="list" class="list-group mb-2"></ul>
						<button type="button" data-type="add" class="btn btn-info">Add block account</button>
					</div>
				</div>

			</form>
		</div>
	</div>
</div>
