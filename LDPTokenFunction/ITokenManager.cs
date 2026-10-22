
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LDPTokenFunction
{
    public interface ITokenManager
    {
        public TokenInfo GetToken();

        public void DeleteToken();

        public bool ValidateUser(string username, string password);
    }
}
