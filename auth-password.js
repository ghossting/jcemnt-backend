const bcrypt = require('bcryptjs');

async function validarSenhaParaLogin(senhaInformada, senhaArmazenada, accessType = 'reader') {
  if (accessType === 'reader') return true;

  if (typeof senhaInformada !== 'string' || senhaInformada.length === 0) {
    return false;
  }

  if (typeof senhaArmazenada !== 'string' || senhaArmazenada.trim().length === 0) {
    return false;
  }

  try {
    if (/^\$2[aby]\$/.test(senhaArmazenada)) {
      return await bcrypt.compare(senhaInformada, senhaArmazenada);
    }

    return senhaInformada === senhaArmazenada;
  } catch (error) {
    console.error('Erro ao validar senha:', error.message);
    return false;
  }
}

module.exports = { validarSenhaParaLogin };