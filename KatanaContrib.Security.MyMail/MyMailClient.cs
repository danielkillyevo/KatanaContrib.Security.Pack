using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Web;

namespace KatanaContrib.Security.MyMail
{
    public class MyMailClient
    {
        #region Fields

        public const string APPSMAIL_API_URL = "http://www.appsmail.ru/platform/api";

        private readonly string _accessToken;
        private readonly string _clientId;
        private readonly string _privateKey;
        private readonly string _userId;

        #endregion

        public MyMailClient(string clientId, string userId, string accessToken, string privateKey)
        {
            _clientId = clientId;
            _userId = userId;
            _accessToken = accessToken;
            _privateKey = privateKey;
        }

        #region Properties

        #endregion

        #region Implementation of IRestApi

        public string BuildMethodRequestUri(string method, IDictionary<string, string> args = null)
        {
            NameValueCollection collection = HttpUtility.ParseQueryString(string.Empty);
            collection.Add("method", method);
            collection.Add("app_id", _clientId.ToString(CultureInfo.InvariantCulture));
            collection.Add("session_key", _accessToken);

            if (args != null)
            {
                foreach (var pair in args)
                {
                    collection.Add(pair.Key, pair.Value);
                }
            }

            string sig = Sign(collection);
            collection.Add("sig", sig);

            return string.Format("{0}?{1}", APPSMAIL_API_URL, collection);
        }

        #endregion

        #region Methods

        private string Sign(NameValueCollection collection)
        {
            //  sig = md5(uid + params + private_key)
            var sb = new StringBuilder(_userId);
            foreach (string key in collection.AllKeys.OrderBy(x => x))
            {
                object value = collection[key];
                if (value != null)
                {
                    sb.AppendFormat("{0}={1}", key, value);
                }
            }

            sb.Append(_privateKey);

            return sb.ToString().GetMd5Hash();
        }

        #endregion
    }
}