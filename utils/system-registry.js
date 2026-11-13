const fs = require('fs');
const path = require('path');

// Perfil especial: todas as funcionalidades ativas do sistema.
const TODOS = '*';

/**
 * Registro dos sistemas (JSON no formato de config/srop.json).
 *
 * Fontes: config/*.json (vão na imagem, só leitura) e data/sistemas/*.json
 * (cadastrados pelo painel). Um sistema do painel com o mesmo mnemônico
 * sobrepõe o de config/. Arquivos *-example.json são ignorados.
 */
function createSystemRegistry(root, { sistemaPadrao } = {}) {
    const fontes = [
        { dir: path.join(root, 'config'), origem: 'config' },
        { dir: path.join(root, 'data', 'sistemas'), origem: 'painel' }
    ];
    const uploadDir = fontes[1].dir;
    const arquivoPadrao = sistemaPadrao ? path.resolve(root, sistemaPadrao) : null;

    let sistemas = new Map();

    function reload() {
        const carregados = new Map();

        fontes.forEach(({ dir, origem }) => {
            readSystemFiles(dir).forEach(({ arquivo, json }) => {
                try {
                    const sistema = parseSistema(json, { arquivo, origem });
                    carregados.set(sistema.mnemonico, sistema);
                } catch (error) {
                    console.warn(`⚠️  Sistema ignorado (${arquivo}): ${error.message}`);
                }
            });
        });

        sistemas = carregados;
        console.log(`🧩 Sistemas carregados: ${[...sistemas.keys()].join(', ') || 'nenhum'}`);
    }

    function list() {
        return [...sistemas.values()].map(sistema => ({
            nome: sistema.nome,
            mnemonico: sistema.mnemonico,
            clientId: sistema.clientId,
            origem: sistema.origem,
            arquivo: path.basename(sistema.arquivo),
            padrao: sistema === findPadrao(),
            todasRoles: buildRoles(sistema, TODOS),
            perfis: listPerfis(sistema).map(nome => ({ nome, roles: buildRoles(sistema, nome) }))
        }));
    }

    function findPadrao() {
        return [...sistemas.values()].find(s => s.arquivo === arquivoPadrao) || null;
    }

    /**
     * Sistema do client: pelo client_id do JSON; senão, o MOCK_SISTEMA_CONFIG.
     */
    function resolve(clientId) {
        return [...sistemas.values()].find(s => s.clientId && s.clientId === clientId) ||
            findPadrao();
    }

    /**
     * Roles do perfil para o client. Sem sistema associado, une as roles
     * do perfil em todos os sistemas (como roles de realm no Keycloak).
     */
    function rolesFor(clientId, perfil) {
        const sistema = resolve(clientId);
        const alvo = sistema ? [sistema] : [...sistemas.values()];

        return [...new Set(alvo.flatMap(s => buildRoles(s, perfil)))];
    }

    function perfis() {
        return [...new Set([...sistemas.values()].flatMap(listPerfis))].sort();
    }

    function save(json) {
        const sistema = parseSistema(json, { arquivo: '', origem: 'painel' });
        const arquivo = path.join(uploadDir, `${sistema.mnemonico.toLowerCase()}.json`);

        fs.mkdirSync(uploadDir, { recursive: true });
        fs.writeFileSync(arquivo, JSON.stringify(json, null, 2));
        reload();

        return sistemas.get(sistema.mnemonico);
    }

    function remove(mnemonico) {
        const sistema = sistemas.get(mnemonico);

        if (!sistema) {
            throw new Error(`Sistema não encontrado: ${mnemonico}`);
        }

        if (sistema.origem !== 'painel') {
            throw new Error('Só sistemas cadastrados pelo painel podem ser removidos.');
        }

        fs.rmSync(sistema.arquivo, { force: true });
        reload();
    }

    reload();

    return { list, resolve, rolesFor, perfis, save, remove, reload };
}

function readSystemFiles(dir) {
    if (!fs.existsSync(dir)) {
        return [];
    }

    return fs.readdirSync(dir)
        .filter(nome => nome.endsWith('.json') && !nome.endsWith('-example.json'))
        .map(nome => path.join(dir, nome))
        .flatMap(arquivo => {
            try {
                return [{ arquivo, json: JSON.parse(fs.readFileSync(arquivo, 'utf8')) }];
            } catch (error) {
                console.warn(`⚠️  JSON inválido ignorado (${arquivo}): ${error.message}`);
                return [];
            }
        });
}

function parseSistema(json, { arquivo, origem }) {
    const sistema = json?.sistema;

    if (!sistema || typeof sistema !== 'object') {
        throw new Error('o JSON precisa ter a chave "sistema".');
    }

    if (!sistema.mnemonico) {
        throw new Error('"sistema.mnemonico" é obrigatório.');
    }

    if (!Array.isArray(sistema.modulos)) {
        throw new Error('"sistema.modulos" precisa ser uma lista.');
    }

    return {
        nome: sistema.nome || sistema.mnemonico,
        mnemonico: String(sistema.mnemonico).toUpperCase(),
        clientId: sistema.client_id || null,
        modulos: sistema.modulos,
        arquivo,
        origem
    };
}

const isAtivo = item => item?.status?.toLowerCase() === 'ativo';

function funcionalidadesAtivas(sistema) {
    return sistema.modulos.filter(isAtivo).flatMap(modulo =>
        (modulo.funcionalidade || []).filter(isAtivo).map(funcionalidade => ({ modulo, funcionalidade }))
    );
}

function buildRoleName(sistema, modulo, funcionalidade) {
    return ['ROLE', sistema.mnemonico, modulo.mnemonico, funcionalidade.mnemonico]
        .join('_')
        .replace(/[^a-zA-Z0-9_]/g, '_')
        .replace(/_+/g, '_')
        .toUpperCase();
}

function buildRoles(sistema, perfil) {
    const alvo = perfil?.trim();
    const todos = !alvo || alvo === TODOS;

    return [...new Set(
        funcionalidadesAtivas(sistema)
            .filter(({ funcionalidade }) =>
                todos || funcionalidade.grupos?.some(grupo => grupo.trim() === alvo)
            )
            .map(({ modulo, funcionalidade }) => buildRoleName(sistema, modulo, funcionalidade))
    )];
}

function listPerfis(sistema) {
    return [...new Set(
        funcionalidadesAtivas(sistema)
            .flatMap(({ funcionalidade }) => funcionalidade.grupos || [])
            .map(grupo => grupo.trim())
            .filter(Boolean)
    )];
}

module.exports = {
    TODOS,
    createSystemRegistry
};
