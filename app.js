const jsonServer = require('json-server');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const dotenv = require('dotenv');

const { loadOrGenerateKeys } = require('./utils/key-manager');
const { createIdentityStore } = require('./utils/identity-store');
const { ROLES, perfilPadrao, sistema, listPerfis } = require('./config/roles');

dotenv.config();

const KID = 'mock-kid';
const REFRESH_TOKEN_EXPIRES_IN = '30d';
const CODE_PREFIX = 'mock.';

function createApp(root) {
    const server = jsonServer.create();

    const config = loadConfig();
    const db = loadDatabase(root);

    configureRealm(db, config);

    const router = jsonServer.router(db);
    const rewriter = createRewriter(root);
    const middlewares = createMiddlewares();

    const keys = createJwtKeys(root);
    const identityStore = createIdentityStore(root, buildDefaultIdentity(config));

    registerHomeRedirect(server);
    registerMiddlewares(server, middlewares);
    registerJwksRoute(server, keys.jwk);
    registerTokenRoute(server, keys.privateKey, config, identityStore);
    registerAccountRoute(server, identityStore);
    registerUserinfoRoute(server, identityStore);
    registerPanelRoutes(server, root, keys.privateKey, config, identityStore);
    registerAuthRoute(server, root);
    registerLogoutRoute(server);
    registerRegistrationRoute(server);

    server.use(rewriter);
    server.use(router);

    return server;
}

/**
 * Carrega as configurações da aplicação.
 */
function loadConfig() {
    const {
        MOCK_KEYCLOAK_REALM,
        MOCK_KEYCLOAK_URL,
        MOCK_USER_SUB,
        MOCK_USER_USERNAME,
        MOCK_USER_EMAIL,
        MOCK_USER_FIRST_NAME,
        MOCK_USER_LAST_NAME,
        MOCK_CLIENT_ID,
        MOCK_ACCESS_TOKEN_EXPIRES_IN,
        MOCK_PAINEL_SENHA
    } = process.env;

    if (!MOCK_KEYCLOAK_REALM) {
        throw new Error(
            'A variável MOCK_KEYCLOAK_REALM não foi definida no arquivo .env'
        );
    }

    if (!MOCK_KEYCLOAK_URL) {
        throw new Error(
            'A variável MOCK_KEYCLOAK_URL não foi definida no arquivo .env'
        );
    }

    return {
        realm: MOCK_KEYCLOAK_REALM,
        baseUrl: MOCK_KEYCLOAK_URL.trim().replace(/\/+$/, ''),
        clientId: MOCK_CLIENT_ID || 'srop-app',
        user: {
            sub: MOCK_USER_SUB,
            username: MOCK_USER_USERNAME,
            email: MOCK_USER_EMAIL,
            firstName: MOCK_USER_FIRST_NAME || 'Usuario',
            lastName: MOCK_USER_LAST_NAME || 'Mock'
        },
        accessTokenExpiresIn:
            MOCK_ACCESS_TOKEN_EXPIRES_IN || '1h',
        painelSenha: MOCK_PAINEL_SENHA?.trim() || ''
    };
}

/**
 * Identidade inicial do mock, montada a partir do .env.
 */
function buildDefaultIdentity(config) {
    return {
        ...config.user,
        roles: ROLES,
        resourceAccess: {},
        extraClaims: {},
        perfil: perfilPadrao || null,
        origem: 'env'
    };
}

/**
 * Carrega o banco de dados JSON.
 */
function loadDatabase(root) {
    const dbPath = path.join(root, 'db.json');

    return require(dbPath);
}

/**
 * Cria o rewriter do JSON Server.
 */
function createRewriter(root) {
    const routesPath = path.join(root, 'routes.json');

    return jsonServer.rewriter(
        require(routesPath)
    );
}

/**
 * Configura os middlewares padrão do JSON Server.
 */
function createMiddlewares() {
    return jsonServer.defaults({
        noCors: false
    });
}

/**
 * Carrega ou gera as chaves RSA utilizadas para assinar os JWTs.
 */
function createJwtKeys(root) {
    const {
        privateKey,
        publicKey
    } = loadOrGenerateKeys(root);

    const publicKeyObject = crypto.createPublicKey(publicKey);

    const jwk = publicKeyObject.export({
        format: 'jwk'
    });

    return {
        privateKey,
        publicKey,
        jwk
    };
}

/**
 * Registra os middlewares padrão.
 */
function registerMiddlewares(server, middlewares) {
    server.use(middlewares);
}

/**
 * Endpoint JWKS.
 *
 * Retorna a chave pública utilizada pelos clientes
 * para validar os tokens JWT.
 */
function registerJwksRoute(server, jwk) {
    server.get(
        '/auth/realms/:realm/protocol/openid-connect/certs',
        (req, res) => {
            console.log(
                '>>> GET /auth/realms/:realm/protocol/openid-connect/certs'
            );

            return res.json({
                keys: [
                    {
                        ...jwk,
                        kid: KID,
                        alg: 'RS256',
                        use: 'sig'
                    }
                ]
            });
        }
    );
}

/**
 * Endpoint de emissão de tokens.
 *
 * Aceita authorization_code (code gerado pelo login.html, que carrega o
 * nonce) e refresh_token. O keycloak-js descarta o token se o nonce
 * não for o mesmo enviado na tela de login.
 */
function registerTokenRoute(server, privateKey, config, identityStore) {
    server.post(
        '/auth/realms/:realm/protocol/openid-connect/token',
        jsonServer.bodyParser,
        (req, res) => {
            const requestedRealm = req.params.realm;
            const body = req.body || {};

            console.log(
                `>>> POST /auth/realms/${requestedRealm}/protocol/openid-connect/token (${body.grant_type || 'sem grant_type'})`
            );

            if (requestedRealm !== config.realm) {
                console.log(
                    `❌ Realm não encontrado: ${requestedRealm}`
                );

                return res.status(404).json({
                    error: 'Realm not found'
                });
            }

            const session = body.grant_type === 'refresh_token'
                ? readSessionFromRefreshToken(body.refresh_token)
                : readSessionFromCode(body.code);

            if (!session) {
                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            session.clientId = body.client_id || session.clientId || config.clientId;

            return res.status(200).json(
                issueTokens(privateKey, config, identityStore.get(), session)
            );
        }
    );
}

/**
 * Emite o conjunto access/refresh/id token para a identidade informada.
 */
function issueTokens(privateKey, config, identity, session) {
    const issuer = buildRealmUrl(
        config.baseUrl,
        config.realm
    );

    return {
        access_token: generateAccessToken(privateKey, issuer, config, identity, session),
        refresh_token: generateRefreshToken(privateKey, issuer, identity, session),
        id_token: generateIdToken(privateKey, issuer, config, identity, session),
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_expires_in: 2592000,
        session_state: session.sid,
        scope: 'openid profile email'
    };
}

/**
 * Lê o nonce embutido no code gerado pelo login.html.
 * Codes sem o prefixo seguem aceitos, sem nonce.
 */
function readSessionFromCode(code) {
    if (!code) {
        return null;
    }

    let nonce;

    if (code.startsWith(CODE_PREFIX)) {
        try {
            const payload = JSON.parse(
                Buffer.from(code.slice(CODE_PREFIX.length), 'base64url').toString('utf8')
            );
            nonce = payload.nonce;
        } catch (error) {
            return null;
        }
    }

    return {
        nonce,
        sid: crypto.randomUUID()
    };
}

/**
 * Recupera nonce/sessão de um refresh token emitido anteriormente.
 */
function readSessionFromRefreshToken(refreshToken) {
    const decoded = refreshToken && jwt.decode(refreshToken);

    if (!decoded || decoded.typ !== 'Refresh') {
        return null;
    }

    return {
        nonce: decoded.nonce,
        sid: decoded.sid || crypto.randomUUID(),
        clientId: decoded.azp
    };
}

/**
 * Claims de identidade do usuário ativo, no formato do Keycloak.
 * Claims extras de um token importado (ex.: atributos customizados) vêm primeiro
 * para nunca sobrescreverem os padrões.
 */
function buildUserClaims(identity) {
    const nomeCompleto = identity.name ||
        [identity.firstName, identity.lastName].filter(Boolean).join(' ');

    const claims = {
        ...identity.extraClaims,
        sub: identity.sub,
        preferred_username: identity.username,
        email: identity.email,
        email_verified: true,
        name: nomeCompleto,
        given_name: identity.firstName,
        family_name: identity.lastName
    };

    return claims;
}

function buildAccessClaims(identity) {
    const claims = {
        realm_access: {
            roles: identity.roles
        }
    };

    if (Object.keys(identity.resourceAccess).length) {
        claims.resource_access = identity.resourceAccess;
    }

    return claims;
}

/**
 * Assina um JWT com a chave privada do mock.
 */
function signToken(privateKey, issuer, payload, expiresIn) {
    return jwt.sign(
        payload,
        privateKey,
        {
            algorithm: 'RS256',
            keyid: KID,
            issuer,
            expiresIn
        }
    );
}

/**
 * Gera o Access Token JWT.
 *
 * typ, azp e sub são exigidos pelo adapter Keycloak do srop-api.
 */
function generateAccessToken(privateKey, issuer, config, identity, session) {
    return signToken(
        privateKey,
        issuer,
        {
            ...buildUserClaims(identity),
            ...buildAccessClaims(identity),
            typ: 'Bearer',
            azp: session.clientId,
            nonce: session.nonce,
            sid: session.sid,
            session_state: session.sid,
            scope: 'openid profile email'
        },
        config.accessTokenExpiresIn
    );
}

/**
 * Gera o Refresh Token JWT.
 */
function generateRefreshToken(privateKey, issuer, identity, session) {
    return signToken(
        privateKey,
        issuer,
        {
            sub: identity.sub,
            preferred_username: identity.username,
            typ: 'Refresh',
            azp: session.clientId,
            nonce: session.nonce,
            sid: session.sid,
            session_state: session.sid
        },
        REFRESH_TOKEN_EXPIRES_IN
    );
}

/**
 * Gera o ID Token JWT.
 */
function generateIdToken(privateKey, issuer, config, identity, session) {
    return signToken(
        privateKey,
        issuer,
        {
            ...buildUserClaims(identity),
            typ: 'ID',
            aud: session.clientId,
            azp: session.clientId,
            nonce: session.nonce,
            sid: session.sid,
            session_state: session.sid
        },
        config.accessTokenExpiresIn
    );
}

/**
 * Endpoint da conta do usuário.
 *
 * Consumido pelo keycloak-js em loadUserProfile().
 */
function registerAccountRoute(server, identityStore) {
    server.get(
        '/auth/realms/:realm/account',
        (req, res) => {
            const identity = identityStore.get();

            return res.json({
                id: identity.sub,
                username: identity.username,
                email: identity.email,
                firstName: identity.firstName,
                lastName: identity.lastName,
                emailVerified: true,
                attributes: {}
            });
        }
    );
}

/**
 * Endpoint userinfo do OIDC, refletindo a identidade ativa.
 */
function registerUserinfoRoute(server, identityStore) {
    server.get(
        '/auth/realms/:realm/protocol/openid-connect/userinfo',
        (req, res) => {
            const identity = identityStore.get();

            return res.json({
                ...buildUserClaims(identity),
                ...buildAccessClaims(identity)
            });
        }
    );
}

/**
 * A raiz abre o painel em vez da home padrão do json-server.
 */
function registerHomeRedirect(server) {
    server.get('/', (req, res) => res.redirect(302, '/painel'));
}

/**
 * Painel de controle: consulta e altera a identidade ativa, troca de perfil,
 * importa um access token real e gera tokens de teste.
 */
function registerPanelRoutes(server, root, privateKey, config, identityStore) {
    const realmUrl = buildRealmUrl(config.baseUrl, config.realm);

    const buildEstado = () => ({
        identidade: identityStore.get(),
        perfis: listPerfis(),
        sistema,
        realm: config.realm,
        clientId: config.clientId,
        issuer: realmUrl,
        endpoints: {
            discovery: `${realmUrl}/.well-known/openid-configuration`,
            auth: `${realmUrl}/protocol/openid-connect/auth`,
            token: `${realmUrl}/protocol/openid-connect/token`,
            certs: `${realmUrl}/protocol/openid-connect/certs`,
            account: `${realmUrl}/account`
        }
    });

    const handle = action => (req, res) => {
        try {
            return res.json(action(req));
        } catch (error) {
            return res.status(400).json({ error: error.message });
        }
    };

    if (config.painelSenha) {
        server.use('/painel', requirePanelPassword(config.painelSenha));
    } else {
        console.warn('⚠️  Painel sem senha: defina MOCK_PAINEL_SENHA se o mock estiver acessível na rede.');
    }

    server.get('/painel', (req, res) => {
        return res.sendFile(path.join(root, 'painel.html'));
    });

    server.get('/painel/api/estado', handle(buildEstado));

    server.put(
        '/painel/api/identidade',
        jsonServer.bodyParser,
        handle(req => {
            identityStore.update(req.body || {});
            console.log('👤 Identidade alterada pelo painel');

            return buildEstado();
        })
    );

    server.post(
        '/painel/api/importar-token',
        jsonServer.bodyParser,
        handle(req => {
            const identity = identityStore.importToken(req.body?.token);
            console.log(`👤 Identidade importada de token: ${identity.username} (${identity.roles.length} roles)`);

            return buildEstado();
        })
    );

    server.post(
        '/painel/api/resetar',
        handle(() => {
            identityStore.reset();
            console.log('👤 Identidade restaurada para os valores do .env');

            return buildEstado();
        })
    );

    server.post(
        '/painel/api/gerar-token',
        handle(() => issueTokens(privateKey, config, identityStore.get(), {
            clientId: config.clientId,
            sid: crypto.randomUUID()
        }))
    );
}

/**
 * Basic Auth do painel: qualquer usuário, senha igual a MOCK_PAINEL_SENHA.
 */
function requirePanelPassword(senha) {
    const esperado = crypto.createHash('sha256').update(senha).digest();

    return (req, res, next) => {
        const [scheme, encoded] = (req.headers.authorization || '').split(' ');
        const credenciais = scheme === 'Basic' && encoded
            ? Buffer.from(encoded, 'base64').toString('utf8')
            : '';
        const recebida = credenciais.slice(credenciais.indexOf(':') + 1);
        const hashRecebido = crypto.createHash('sha256').update(recebida).digest();

        if (credenciais && crypto.timingSafeEqual(esperado, hashRecebido)) {
            return next();
        }

        res.set('WWW-Authenticate', 'Basic realm="Painel Mock Keycloak", charset="UTF-8"');

        return res.status(401).send('Autenticação necessária.');
    };
}

/**
 * Endpoint de autenticação.
 *
 * Simula a tela de login do Keycloak.
 */
function registerAuthRoute(server, root) {
    server.get(
        '/auth/realms/:realm/protocol/openid-connect/auth',
        (req, res) => {
            return res.sendFile(
                path.join(root, 'login.html')
            );
        }
    );
}

/**
 * Endpoint de logout.
 */
function registerLogoutRoute(server) {
    server.get(
        '/auth/realms/:realm/protocol/openid-connect/logout',
        (req, res) => {
            const redirect =
                req.query.post_logout_redirect_uri ||
                req.query.redirect_uri;

            if (redirect) {
                return res.redirect(
                    302,
                    redirect
                );
            }

            return res.status(204).end();
        }
    );
}

/**
 * Mock do endpoint de registro de usuário.
 */
function registerRegistrationRoute(server) {
    server.use((req, res, next) => {
        const isRegistrationRequest =
            req.method === 'POST' &&
            req.url.includes('/registrations');

        if (!isRegistrationRequest) {
            return next();
        }

        return res.status(201).json({
            message: 'User registered successfully (Mock)'
        });
    });
}

/**
 * Configura os endpoints de descoberta do OpenID Connect
 * e informações do Realm.
 */
function configureRealm(db, config) {
    const realmBaseUrl = buildRealmUrl(
        config.baseUrl,
        config.realm
    );

    db['openid-configuration'] = {
        ...db['openid-configuration'],

        issuer: realmBaseUrl,

        authorization_endpoint:
            `${realmBaseUrl}/protocol/openid-connect/auth`,

        token_endpoint:
            `${realmBaseUrl}/protocol/openid-connect/token`,

        userinfo_endpoint:
            `${realmBaseUrl}/protocol/openid-connect/userinfo`,

        end_session_endpoint:
            `${realmBaseUrl}/protocol/openid-connect/logout`,

        jwks_uri:
            `${realmBaseUrl}/protocol/openid-connect/certs`
    };

    db['realm-info'] = {
        ...db['realm-info'],

        realm: config.realm,

        'token-service':
            `${realmBaseUrl}/protocol/openid-connect`,

        'account-service':
            `${realmBaseUrl}/account`
    };

    return db;
}

/**
 * Monta a URL base do Realm.
 */
function buildRealmUrl(baseUrl, realm) {
    return `${baseUrl}/auth/realms/${realm}`;
}

module.exports = createApp;
