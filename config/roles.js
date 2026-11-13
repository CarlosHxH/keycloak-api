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

const ROLES = [];

const sistema = config.sistema;
const MOCK_PERFIL = process.env.MOCK_PERFIL?.trim();

sistema.modulos.forEach(modulo => {
    if (modulo.status?.toLowerCase() !== 'ativo') {
        return;
    }

    modulo.funcionalidade.forEach(funcionalidade => {
        if (funcionalidade.status?.toLowerCase() !== 'ativo') {
            return;
        }

        // Se MOCK_PERFIL estiver definido, filtra pelo perfil.
        // Se não estiver definido, considera todas as funcionalidades ativas.
        if (
            MOCK_PERFIL &&
            !funcionalidade.grupos?.some(
                grupo => grupo.trim() === MOCK_PERFIL
            )
        ) {
            return;
        }

        const role = [
            'ROLE',
            sistema.mnemonico,
            modulo.mnemonico,
            funcionalidade.mnemonico
        ]
            .join('_')
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/_+/g, '_')
            .toUpperCase();

        if (!ROLES.includes(role)) {
            ROLES.push(role);
        }
    });
});

module.exports = ROLES;
