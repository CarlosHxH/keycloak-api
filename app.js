const jsonServer = require('json-server');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const dotenv = require('dotenv');

const { loadOrGenerateKeys } = require('./utils/key-manager');
const { createIdentityStore } = require('./utils/identity-store');
const { createSystemRegistry, TODOS } = require('./utils/system-registry');

dotenv.config();

const KID = 'mock-kid';
const REFRESH_TOKEN_EXPIRES_IN = '30d';
const CODE_EXPIRES_IN = '5m';
const DEFAULT_ADMIN = 'admin';
const DEFAULT_REALM = 'master';
const DEFAULT_CLIENT = 'account';

function createApp(root) {
    const server = jsonServer.create();

    const config = loadConfig();
    const db = loadDatabase(root);

    const router = jsonServer.router(db);
    const rewriter = createRewriter(root);
    const middlewares = createMiddlewares();

    const keys = createJwtKeys(root);
    const systems = createSystemRegistry(root, { sistemaPadrao: config.sistemaPadrao });
    const identityStore = createIdentityStore(root, buildDefaultIdentity(config));

    const ctx = { config, keys, systems, identityStore };

    registerHomeRedirect(server);
    registerMiddlewares(server, middlewares);
    registerDiscoveryRoutes(server, ctx);
    registerJwksRoute(server, keys.jwk);
    registerLoginRoute(server, ctx);
    registerTokenRoute(server, ctx);
    registerAccountRoute(server, ctx);
    registerUserinfoRoute(server, ctx);
    registerPanelRoutes(server, root, ctx);
    registerAuthRoute(server, root);
    registerLogoutRoute(server);
    registerRegistrationRoute(server);

    server.use(rewriter);
    server.use(router);

    return server;
}

/**
 * Carrega as configurações da aplicação.
 *
 * Realm e client vêm de cada requisição; MOCK_KEYCLOAK_REALM e MOCK_CLIENT_ID
 * são só os valores sugeridos no painel.
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
        MOCK_SISTEMA_CONFIG,
        MOCK_PERFIL,
        MOCK_ACCESS_TOKEN_EXPIRES_IN,
        MOCK_ADMIN_USUARIO,
        MOCK_ADMIN_SENHA
    } = process.env;

    if (!MOCK_KEYCLOAK_URL) {
        throw new Error(
            'A variável MOCK_KEYCLOAK_URL não foi definida no arquivo .env'
        );
    }

    return {
        baseUrl: MOCK_KEYCLOAK_URL.trim().replace(/\/+$/, ''),
        realmPadrao: MOCK_KEYCLOAK_REALM?.trim() || DEFAULT_REALM,
        clientPadrao: MOCK_CLIENT_ID?.trim() || DEFAULT_CLIENT,
        sistemaPadrao: MOCK_SISTEMA_CONFIG?.trim() || null,
        perfilPadrao: MOCK_PERFIL?.trim() || TODOS,
        user: {
            sub: MOCK_USER_SUB,
            username: MOCK_USER_USERNAME,
            email: MOCK_USER_EMAIL,
            firstName: MOCK_USER_FIRST_NAME || 'Usuario',
            lastName: MOCK_USER_LAST_NAME || 'Mock'
        },
        accessTokenExpiresIn:
            MOCK_ACCESS_TOKEN_EXPIRES_IN || '1h',
        admin: loadAdminCredentials(MOCK_ADMIN_USUARIO, MOCK_ADMIN_SENHA)
    };
}

/**
 * Credenciais exigidas na tela de login e no painel (padrão admin/admin).
 */
function loadAdminCredentials(usuario, senha) {
    const admin = {
        usuario: usuario?.trim() || DEFAULT_ADMIN,
        senha: senha?.trim() || DEFAULT_ADMIN
    };

    if (admin.senha === DEFAULT_ADMIN) {
        console.warn('⚠️  Usando a senha padrão "admin": defina MOCK_ADMIN_SENHA se o mock estiver acessível na rede.');
    }

    return admin;
}

function sameSecret(esperado, recebido) {
    const hash = valor => crypto.createHash('sha256').update(String(valor ?? '')).digest();

    return crypto.timingSafeEqual(hash(esperado), hash(recebido));
}

function isValidLogin(admin, usuario, senha) {
    const usuarioOk = sameSecret(admin.usuario, usuario);
    const senhaOk = sameSecret(admin.senha, senha);

    return usuarioOk && senhaOk;
}

/**
 * Identidade inicial do mock, montada a partir do .env.
 *
 * Com perfil definido, as roles são calculadas por client (sistema) a cada token.
 */
function buildDefaultIdentity(config) {
    return {
        ...config.user,
        roles: [],
        resourceAccess: {},
        extraClaims: {},
        perfil: config.perfilPadrao,
        origem: 'env'
    };
}

/**
 * Identidade com as roles efetivas para o client: as roles do perfil no
 * sistema do client, ou a lista fixa (token importado / roles personalizadas).
 */
function resolveIdentity(ctx, clientId) {
    const identity = ctx.identityStore.get();

    if (identity.origem !== 'token' && identity.perfil) {
        identity.roles = ctx.systems.rolesFor(clientId, identity.perfil);
    }

    return identity;
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

    const publicKeyBase64 = publicKeyObject
        .export({ type: 'spki', format: 'der' })
        .toString('base64');

    return {
        privateKey,
        publicKey,
        publicKeyBase64,
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
 * Discovery do OIDC e informações do realm, montados para o realm da URL.
 */
function registerDiscoveryRoutes(server, { config, keys }) {
    server.get(
        '/auth/realms/:realm/.well-known/openid-configuration',
        (req, res) => {
            const realmUrl = buildRealmUrl(config.baseUrl, req.params.realm);

            return res.json({
                issuer: realmUrl,
                authorization_endpoint: `${realmUrl}/protocol/openid-connect/auth`,
                token_endpoint: `${realmUrl}/protocol/openid-connect/token`,
                userinfo_endpoint: `${realmUrl}/protocol/openid-connect/userinfo`,
                end_session_endpoint: `${realmUrl}/protocol/openid-connect/logout`,
                jwks_uri: `${realmUrl}/protocol/openid-connect/certs`,
                grant_types_supported: ['authorization_code', 'refresh_token', 'password'],
                response_types_supported: ['code'],
                response_modes_supported: ['query', 'fragment'],
                id_token_signing_alg_values_supported: ['RS256'],
                subject_types_supported: ['public'],
                scopes_supported: ['openid', 'profile', 'email']
            });
        }
    );

    server.get(
        '/auth/realms/:realm',
        (req, res) => {
            const realmUrl = buildRealmUrl(config.baseUrl, req.params.realm);

            return res.json({
                realm: req.params.realm,
                public_key: keys.publicKeyBase64,
                'token-service': `${realmUrl}/protocol/openid-connect`,
                'account-service': `${realmUrl}/account`,
                'tokens-not-before': 0
            });
        }
    );
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
 * Valida usuário/senha da tela de login e devolve o authorization code.
 *
 * O code é um JWT assinado pelo mock com o nonce do keycloak-js, o realm e o
 * client, então não pode ser forjado no navegador para pular a senha.
 */
function registerLoginRoute(server, { config, keys }) {
    server.post(
        '/auth/realms/:realm/login-actions/authenticate',
        jsonServer.bodyParser,
        (req, res) => {
            const { username, password, nonce, client_id: clientId } = req.body || {};

            if (!isValidLogin(config.admin, username, password)) {
                console.log(`❌ Login recusado para "${username || ''}"`);

                return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
            }

            const code = jwt.sign(
                {
                    typ: 'Code',
                    nonce: nonce || undefined,
                    realm: req.params.realm,
                    azp: clientId || undefined
                },
                keys.privateKey,
                { algorithm: 'RS256', keyid: KID, expiresIn: CODE_EXPIRES_IN }
            );

            return res.json({ code });
        }
    );
}

/**
 * Endpoint de emissão de tokens.
 *
 * Aceita authorization_code (code emitido no login, com o nonce), refresh_token
 * e password, para qualquer realm. O keycloak-js descarta o token se o nonce
 * não for o mesmo enviado na tela de login.
 */
function registerTokenRoute(server, ctx) {
    const { config, keys } = ctx;

    server.post(
        '/auth/realms/:realm/protocol/openid-connect/token',
        jsonServer.bodyParser,
        (req, res) => {
            const { realm } = req.params;
            const body = req.body || {};
            const grantType = body.grant_type || 'authorization_code';

            console.log(
                `>>> POST /auth/realms/${realm}/protocol/openid-connect/token (${grantType}, client ${body.client_id || '—'})`
            );

            const readers = {
                authorization_code: () => readSessionFromCode(body.code, keys.publicKey, realm),
                refresh_token: () => readSessionFromRefreshToken(
                    body.refresh_token,
                    keys.publicKey,
                    buildRealmUrl(config.baseUrl, realm)
                ),
                password: () => isValidLogin(config.admin, body.username, body.password)
                    ? { sid: crypto.randomUUID() }
                    : null
            };

            if (!readers[grantType]) {
                return res.status(400).json({
                    error: 'unsupported_grant_type'
                });
            }

            const session = readers[grantType]();

            if (!session) {
                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            session.realm = realm;
            session.clientId = body.client_id || session.clientId || config.clientPadrao;

            return res.status(200).json(
                issueTokens(ctx, session)
            );
        }
    );
}

/**
 * Emite o conjunto access/refresh/id token da identidade ativa para a sessão.
 */
function issueTokens(ctx, session) {
    const { config, keys } = ctx;
    const identity = resolveIdentity(ctx, session.clientId);
    const issuer = buildRealmUrl(config.baseUrl, session.realm);

    return {
        access_token: generateAccessToken(keys.privateKey, issuer, config, identity, session),
        refresh_token: generateRefreshToken(keys.privateKey, issuer, identity, session),
        id_token: generateIdToken(keys.privateKey, issuer, config, identity, session),
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_expires_in: 2592000,
        session_state: session.sid,
        scope: 'openid profile email'
    };
}

/**
 * Verifica um JWT emitido pelo próprio mock e confere o typ esperado.
 */
function verifyOwnToken(token, publicKey, typ, options = {}) {
    try {
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'], ...options });

        return decoded.typ === typ ? decoded : null;
    } catch (error) {
        return null;
    }
}

/**
 * Lê o nonce/client do code emitido em /login-actions/authenticate.
 * O code só vale no realm em que o login foi feito.
 */
function readSessionFromCode(code, publicKey, realm) {
    const decoded = code && verifyOwnToken(code, publicKey, 'Code');

    if (!decoded || decoded.realm !== realm) {
        return null;
    }

    return {
        nonce: decoded.nonce,
        clientId: decoded.azp,
        sid: crypto.randomUUID()
    };
}

/**
 * Recupera nonce/sessão de um refresh token emitido para o mesmo realm.
 */
function readSessionFromRefreshToken(refreshToken, publicKey, issuer) {
    const decoded = refreshToken && verifyOwnToken(refreshToken, publicKey, 'Refresh', { issuer });

    if (!decoded) {
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

    return {
        ...identity.extraClaims,
        sub: identity.sub,
        preferred_username: identity.username,
        email: identity.email,
        email_verified: true,
        name: nomeCompleto,
        given_name: identity.firstName,
        family_name: identity.lastName
    };
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
 * Client do access token enviado no header Authorization (claim azp).
 */
function clientFromBearer(req, publicKey) {
    const [scheme, token] = (req.headers.authorization || '').split(' ');

    if (!/^bearer$/i.test(scheme || '') || !token) {
        return null;
    }

    return verifyOwnToken(token, publicKey, 'Bearer')?.azp || null;
}

/**
 * Endpoint da conta do usuário.
 *
 * Consumido pelo keycloak-js em loadUserProfile().
 */
function registerAccountRoute(server, { identityStore }) {
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
 * Endpoint userinfo do OIDC, com as roles do client do token recebido.
 */
function registerUserinfoRoute(server, ctx) {
    server.get(
        '/auth/realms/:realm/protocol/openid-connect/userinfo',
        (req, res) => {
            const clientId = clientFromBearer(req, ctx.keys.publicKey) || ctx.config.clientPadrao;
            const identity = resolveIdentity(ctx, clientId);

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
 * Painel de controle: identidade ativa, perfis, importação de access token,
 * cadastro de sistemas e geração de tokens de teste para qualquer realm/client.
 */
function registerPanelRoutes(server, root, ctx) {
    const { config, systems, identityStore } = ctx;

    const buildEstado = () => ({
        identidade: identityStore.get(),
        sistemas: systems.list(),
        perfis: systems.perfis(),
        perfilTodos: TODOS,
        baseUrl: config.baseUrl,
        realmPadrao: config.realmPadrao,
        clientPadrao: config.clientPadrao
    });

    const handle = action => (req, res) => {
        try {
            return res.json(action(req));
        } catch (error) {
            return res.status(400).json({ error: error.message });
        }
    };

    server.use('/painel', requireAdminCredentials(config.admin));

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
        '/painel/api/sistemas',
        jsonServer.bodyParser,
        handle(req => {
            const sistema = systems.save(req.body);
            console.log(`🧩 Sistema cadastrado pelo painel: ${sistema.mnemonico} (client ${sistema.clientId || '—'})`);

            return buildEstado();
        })
    );

    server.delete(
        '/painel/api/sistemas/:mnemonico',
        handle(req => {
            systems.remove(req.params.mnemonico);
            console.log(`🧩 Sistema removido pelo painel: ${req.params.mnemonico}`);

            return buildEstado();
        })
    );

    server.post(
        '/painel/api/gerar-token',
        jsonServer.bodyParser,
        handle(req => {
            const realm = req.body?.realm?.trim() || config.realmPadrao;
            const clientId = req.body?.clientId?.trim() || config.clientPadrao;
            const tokens = issueTokens(ctx, { realm, clientId, sid: crypto.randomUUID() });

            return {
                ...tokens,
                realm,
                clientId,
                roles: jwt.decode(tokens.access_token).realm_access.roles
            };
        })
    );
}

/**
 * Basic Auth do painel com as mesmas credenciais da tela de login.
 */
function requireAdminCredentials(admin) {
    return (req, res, next) => {
        const [scheme, encoded] = (req.headers.authorization || '').split(' ');
        const credenciais = scheme === 'Basic' && encoded
            ? Buffer.from(encoded, 'base64').toString('utf8')
            : '';
        const separador = credenciais.indexOf(':');

        if (
            separador > -1 &&
            isValidLogin(admin, credenciais.slice(0, separador), credenciais.slice(separador + 1))
        ) {
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
 * Monta a URL base do Realm.
 */
function buildRealmUrl(baseUrl, realm) {
    return `${baseUrl}/auth/realms/${realm}`;
}

module.exports = createApp;
