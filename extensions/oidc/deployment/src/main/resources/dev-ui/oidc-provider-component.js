import { LitElement, html, css} from 'lit';
import { JsonRpc } from 'jsonrpc';
import '@vaadin/icon';
import '@vaadin/button';
import { until } from 'lit/directives/until.js';
import '@vaadin/grid';
import '@vaadin/grid/vaadin-grid-selection-column.js';
import { oidcProviderName } from 'build-time-data'; // nullable
import { oidcApplicationType } from 'build-time-data';
import { oidcGrantType } from 'build-time-data';
import { swaggerIsAvailable } from 'build-time-data';
import { graphqlIsAvailable } from 'build-time-data';
import { introspectionIsAvailable } from 'build-time-data';
import { clientIdSupplier } from 'build-time-data';
import { clientSecretSupplier } from 'build-time-data';
import { authorizationUrlSupplier } from 'build-time-data';
import { tokenUrlSupplier } from 'build-time-data';
import { logoutUrlSupplier } from 'build-time-data';
import { postLogoutUriParamSupplier } from 'build-time-data';


export class OidcProviderComponent extends LitElement {

    static styles = css`
        .full-height {
          height: 100%;
        }
    `;

    jsonRpc = new JsonRpc(this);

    // FIXME
    static properties = {
        _persistenceUnits: {state: true, type: Array},
        _selectedEntityTypes: {state: true, type: Object}
    }

    connectedCallback() {
        super.connectedCallback();
        // FIXME
        this.jsonRpc.getInfo().then(response => {
            this._persistenceUnits = response.result.persistenceUnits;
            this._selectedEntityTypes = {};
            this._persistenceUnits.forEach(pu => {
                this._selectedEntityTypes[pu.name] = [];
            });
        });
    }

    render() {
        return html`${until(this._renderProvider(), html`<span>Loading...</span>`)}`;
    }

    _renderProvider() {
        // FIXME
    }

    _webAppLoginCard() {
        return html`
            <div class="card">
                <div class="card-body">
                    <div class="row">
                        <div class="col-2">
                            <label for="servicePath">Service Path</label>
                        </div>
                        <div class="col-10">
                            <input type="text" class="form-control" id="servicePath" value="/" title="Service Path">
                        </div>
                    </div>
                    <div class="row my-2">
                        <div class="col offset-md-2">
                            <button onclick="signInToService(getServicePath());" class="btn btn-success btn-block" title="Log into your Web Application">Log into your Web Application</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

}
customElements.define('oidc-provider-component', OidcProviderComponent);