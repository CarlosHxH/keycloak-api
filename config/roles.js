const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

// MOCK_SISTEMA_CONFIG aponta o JSON do sistema (ex.: config/srop.json),
// relativo à raiz do projeto. Sem ela, usa config/config.json.
const configPath = path.resolve(
    __dirname,
    '..',
    process.env.MOCK_SISTEMA_CONFIG?.trim() || 'config/config.json'
);

if (!fs.existsSync(configPath)) {
    throw new Error(
        `Arquivo de configuração do sistema não encontrado: ${configPath}. ` +
        'Defina MOCK_SISTEMA_CONFIG (ex.: config/srop.json) ou crie config/config.json.'
    );
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const sistema = config.sistema;

const isAtivo = item => item.status?.toLowerCase() === 'ativo';

function buildRoleName(modulo, funcionalidade) {
    return [
        'ROLE',
        sistema.mnemonico,
        modulo.mnemonico,
        funcionalidade.mnemonico
    ]
        .join('_')
        .replace(/[^a-zA-Z0-9_]/g, '_')
        .replace(/_+/g, '_')
        .toUpperCase();
}

/**
 * Roles das funcionalidades ativas do perfil informado.
 * Sem perfil, considera todas as funcionalidades ativas.
 */
function buildRoles(perfil) {
    const roles = [];
    const perfilAlvo = perfil?.trim();

    sistema.modulos.filter(isAtivo).forEach(modulo => {
        modulo.funcionalidade.filter(isAtivo).forEach(funcionalidade => {
            if (
                perfilAlvo &&
                !funcionalidade.grupos?.some(grupo => grupo.trim() === perfilAlvo)
            ) {
                return;
            }

            const role = buildRoleName(modulo, funcionalidade);

            if (!roles.includes(role)) {
                roles.push(role);
            }
        });
    });

    return roles;
}

/**
 * Perfis (grupos) declarados no JSON do sistema, com suas roles.
 */
function listPerfis() {
    const nomes = new Set();

    sistema.modulos.filter(isAtivo).forEach(modulo => {
        modulo.funcionalidade.filter(isAtivo).forEach(funcionalidade => {
            funcionalidade.grupos?.forEach(grupo => nomes.add(grupo.trim()));
        });
    });

    return [...nomes]
        .filter(Boolean)
        .map(nome => ({ nome, roles: buildRoles(nome) }));
}

module.exports = {
    sistema: sistema.mnemonico,
    perfilPadrao: process.env.MOCK_PERFIL?.trim() || '',
    ROLES: buildRoles(process.env.MOCK_PERFIL),
    buildRoles,
    listPerfis
};
