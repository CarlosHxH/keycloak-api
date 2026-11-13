const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

// Claims de protocolo/sessão: o mock sempre gera os seus, nunca copia do token importado.
const PROTOCOL_CLAIMS = [
    'exp', 'iat', 'nbf', 'jti', 'iss', 'aud', 'typ', 'azp', 'nonce',
    'sid', 'session_state', 'auth_time', 'acr', 'at_hash', 'scope',
    'allowed-origins'
];

// Claims de identidade mapeados para campos próprios da identidade.
const IDENTITY_CLAIMS = [
    'sub', 'preferred_username', 'email', 'email_verified', 'name',
    'given_name', 'family_name', 'realm_access', 'resource_access'
];

/**
 * Guarda a identidade que o mock usa ao emitir tokens.
 *
 * Começa com os valores do .env e pode ser alterada pelo painel
 * (edição manual ou importação de um access token real). As alterações
 * ficam em data/identity.json para sobreviver a restarts; onde o disco
 * não é gravável (Netlify), ficam só em memória.
 */
function createIdentityStore(root, defaults) {
    const filePath = path.join(root, 'data', 'identity.json');

    let identity = readFromDisk(filePath) || clone(defaults);

    function get() {
        return clone(identity);
    }

    function update(changes) {
        identity = normalize({
            ...identity,
            ...pickEditable(changes),
            origem: 'manual',
            atualizadoEm: new Date().toISOString()
        });

        persist();

        return get();
    }

    function importToken(rawToken) {
        const payload = decodeToken(rawToken);

        const extraClaims = Object.fromEntries(
            Object.entries(payload).filter(
                ([claim]) => !PROTOCOL_CLAIMS.includes(claim) && !IDENTITY_CLAIMS.includes(claim)
            )
        );

        identity = normalize({
            sub: payload.sub,
            username: payload.preferred_username,
            email: payload.email,
            firstName: payload.given_name,
            lastName: payload.family_name,
            name: payload.name,
            roles: payload.realm_access?.roles || [],
            resourceAccess: payload.resource_access || {},
            extraClaims,
            perfil: null,
            origem: 'token',
            tokenImportado: {
                iss: payload.iss,
                azp: payload.azp,
                exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : null
            },
            atualizadoEm: new Date().toISOString()
        });

        persist();

        return get();
    }

    function reset() {
        identity = clone(defaults);

        try {
            fs.rmSync(filePath, { force: true });
        } catch (error) {
            console.warn(`⚠️  Não foi possível remover ${filePath}: ${error.message}`);
        }

        return get();
    }

    function persist() {
        try {
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
            fs.writeFileSync(filePath, JSON.stringify(identity, null, 2));
        } catch (error) {
            console.warn(`⚠️  Identidade mantida só em memória: ${error.message}`);
        }
    }

    return { get, update, importToken, reset };
}

/**
 * Decodifica o payload sem validar assinatura: o token vem de outro
 * Keycloak (ex.: dev2), cuja chave o mock não conhece. Só os claims são usados.
 */
function decodeToken(rawToken) {
    const token = String(rawToken || '')
        .trim()
        .replace(/^bearer\s+/i, '');

    const payload = jwt.decode(token);

    if (!payload || typeof payload !== 'object') {
        throw new Error('Token inválido: não foi possível decodificar o JWT.');
    }

    if (!payload.sub) {
        throw new Error('Token sem o claim "sub".');
    }

    return payload;
}

function pickEditable(changes = {}) {
    const editable = [
        'sub', 'username', 'email', 'firstName', 'lastName', 'name',
        'roles', 'resourceAccess', 'extraClaims', 'perfil'
    ];

    return Object.fromEntries(
        Object.entries(changes).filter(([key]) => editable.includes(key))
    );
}

function normalize(identity) {
    const roles = Array.isArray(identity.roles)
        ? [...new Set(identity.roles.map(role => String(role).trim()).filter(Boolean))]
        : [];

    return {
        ...identity,
        roles,
        resourceAccess: isPlainObject(identity.resourceAccess) ? identity.resourceAccess : {},
        extraClaims: isPlainObject(identity.extraClaims) ? identity.extraClaims : {}
    };
}

function readFromDisk(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            return null;
        }

        console.log(`👤 Identidade carregada de ${filePath}`);

        return normalize(JSON.parse(fs.readFileSync(filePath, 'utf8')));
    } catch (error) {
        console.warn(`⚠️  Ignorando ${filePath}: ${error.message}`);

        return null;
    }
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

module.exports = {
    createIdentityStore
};
