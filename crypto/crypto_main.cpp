#include <libdevcore/Common.h>
#include <libdevcrypto/Common.h>
#include <libdevcore/Base64.h>
#include <libdevcrypto/Hash.h>
#include <libdevcore/FixedHash.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <crypto/sm2.h>
#include <crypto/sm4.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <sys/time.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <vector>

using namespace std;
using namespace dev;
using namespace dev::crypto;
class GMCrypto
{
public:
    using Ptr = std::shared_ptr<GMCrypto>;
    std::string sm4Encrypt(std::string const& _plainData, std::string const& _key)
    {
        SM4_KEY sm4Key;
        SM4_set_key((const byte*)_key.data(), &sm4Key);
        std::string ciperData;
        SM4_encrypt((const byte*)_plainData.data(), (byte*)ciperData.data(), &sm4Key);
        return ciperData;
    }

    string sm4Decrypt(const string& _cypherData, const string& _key)
    {
        SM4_KEY sm4Key;
        SM4_set_key((const byte*)_key.data(), &sm4Key);
        std::string plainData;
        SM4_decrypt((const byte*)_cypherData.data(), (byte*)plainData.size(), &sm4Key);
        return plainData;
    }

    void sm2Sign(const char* _originalData, int _originalDataLen, const string& _privateKeyHex,
        string& _r, string& _s)
    {
        // create EC_GROUP
        EC_GROUP* sm2Group = EC_GROUP_new_by_curve_name(NID_sm2);
        BIGNUM* privateKey;

        EC_KEY* sm2Key = NULL;
        EC_POINT* point = NULL;

        ECDSA_SIG* sig = NULL;

        const BIGNUM* sigR = NULL;
        const BIGNUM* sigS = NULL;
        char* sPtr = NULL;
        char* rPtr = NULL;
        if (!BN_hex2bn(&privateKey, _privateKeyHex.data()))
        {
            std::cout << "[SM2:sign] ERROR of BN_hex2bn privateKey: " << _privateKeyHex
                      << std::endl;
            goto done;
        }

        sm2Key = EC_KEY_new();
        if (sm2Key == NULL)
        {
            std::cout << "[SM2::sign] ERROR of EC_KEY_new" << std::endl;
            goto done;
        }
        if (!EC_KEY_set_group(sm2Key, sm2Group))
        {
            std::cout << "[SM2::sign] ERROR of EC_KEY_set_group" << std::endl;
            goto done;
        }
        if (!EC_KEY_set_private_key(sm2Key, privateKey))
        {
            std::cout << "[SM2::sign] ERROR of EC_KEY_set_private_key" << std::endl;
            goto done;
        }

        point = EC_POINT_new(sm2Group);
        if (!point)
        {
            std::cout << "[SM2::sign] ERROR of EC_POINT_new" << std::endl;
            goto done;
        }

        sig = sm2_do_sign(sm2Key, NULL, NULL, 0, (const uint8_t*)_originalData, _originalDataLen);
        if (sig == NULL)
        {
            std::cout << "[SM2::sign] ERROR of sm2_do_sign" << std::endl;
            goto done;
        }

        ECDSA_SIG_get0(sig, &sigR, &sigS);
        sPtr = BN_bn2hex(sigS);
        rPtr = BN_bn2hex(sigR);
        _s = sPtr;
        _r = rPtr;
    done:
        ECDSA_SIG_free(sig);
        EC_POINT_free(point);
        EC_KEY_free(sm2Key);
        BN_free(privateKey);
    }

    int sm2Verify(const string& _signData, int, const char* _originalData, int _originalDataLen,
        const string& _publicKeyHex)
    {
        EC_KEY* sm2Key = NULL;
        EC_POINT* point = NULL;
        ECDSA_SIG* sig = NULL;
        BIGNUM* rBigNum = NULL;
        BIGNUM* sBigNum = NULL;
        int ok = 0;
        string r = _signData.substr(0, 64);
        string s = _signData.substr(64, 64);
        EC_GROUP* sm2Group = EC_GROUP_new_by_curve_name(NID_sm2);

        point = EC_POINT_new(sm2Group);
        if (!point)
        {
            std::cout << "[SM2::verify] ERROR of EC_POINT_new" << std::endl;
            goto done;
        }
        if (!EC_POINT_hex2point(sm2Group, (const char*)_publicKeyHex.c_str(), point, NULL))
        {
            std::cout << "[SM2::veify] ERROR of Verify EC_POINT_hex2point" << std::endl;
            goto done;
        }

        sm2Key = EC_KEY_new();
        if (sm2Key == NULL)
        {
            std::cout << "[SM2::verify] ERROR of EC_KEY_new" << std::endl;
            goto done;
        }

        if (!EC_KEY_set_group(sm2Key, sm2Group))
        {
            std::cout << "[SM2::verify] ERROR of EC_KEY_set_group" << std::endl;
            goto done;
        }
        if (!EC_KEY_set_public_key(sm2Key, point))
        {
            std::cout << "[SM2::verify] ERROR of EC_KEY_set_public_key" << std::endl;
            goto done;
        }
        sig = ECDSA_SIG_new();
        if (!BN_hex2bn(&rBigNum, r.c_str()))
        {
            std::cout << "[SM2::verify] ERROR of BN_hex2bn for r:" << r << std::endl;
            goto done;
        }

        if (!BN_hex2bn(&sBigNum, s.c_str()))
        {
            std::cout << "[SM2::verify] ERROR of BN_hex2bn for s:" << s << std::endl;
            goto done;
        }
        if(!ECDSA_SIG_set0(sig, rBigNum, sBigNum))
        {
             std::cout << "[SM2::verify] ERROR of ECDSA_SIG_set0 failed" << std::endl;
            goto done;
        }
        ok = sm2_do_verify(
            sm2Key, NULL, sig, NULL, 0, (const uint8_t*)_originalData, _originalDataLen);
    done:
        ECDSA_SIG_free(sig);
        EC_POINT_free(point);
        EC_KEY_free(sm2Key);
        BN_free(rBigNum);
        BN_free(sBigNum);
        return ok;
    }
};

class CryptoTest
{
public:
    CryptoTest() { m_gmCrypto = std::make_shared<GMCrypto>(); }

    h1024 sign(Secret const& _k, h256 const& _hash, h512 const& _pub)
    {
        string pri = toHex(bytesConstRef{_k.data(), 32});
        string r = "", s = "";
        m_gmCrypto->sm2Sign((const char*)_hash.data(), h256::size, pri, r, s);
        //std::string pub = m_gmCrypto->priToPub(pri);
        bytes byteSign = fromHex(r + s) + _pub.asBytes();
        return h1024{byteSign};
    }


    bool verify(Public const& _p, h1024 const& _s, h256 const& _hash)
    {
        string signData = toHex(_s.asBytes());
        string pub = toHex(_p.asBytes());
        pub = "04" + pub;
        bool ret = m_gmCrypto->sm2Verify(
            signData, signData.length(), (const char*)_hash.data(), h256::size, pub);
        return ret;
    }

    std::string sm4Encrypt(std::string const& _plainData, std::string const& _key)
    {
        return m_gmCrypto->sm4Encrypt(_plainData, _key);
    }

    string sm4Decrypt(const string& _cypherData, const string& _key)
    {
        return m_gmCrypto->sm4Decrypt(_cypherData, _key);
    }

private:
    GMCrypto::Ptr m_gmCrypto;
};

int main()
{
    std::shared_ptr<CryptoTest> crypto = std::make_shared<CryptoTest>();

    auto repeatCount = 1000000;

    cout << "Testing encrypt/decrypt performace"
         << " ..." << endl;
    cout << "[repeatCount] = " << repeatCount << endl;
    auto key = string("0123456789ABCDEF");
    auto data = string(
        "A communication between President Donald Trump and a "
        "world leader prompted a "
        "whistleblower complaint that is now at the center of a "
        "dispute between the director of "
        "national intelligence and Congress, a source familiar "
        "with the case told CNN.");

    auto encryptedData = string();
    auto startTime = utcTime();
    for (auto i = 0; i < repeatCount; ++i)
    {
        encryptedData = crypto->sm4Encrypt(data, key);
    }
    auto endTime = utcTime();
    auto encryptCost = endTime - startTime;
    encryptCost = encryptCost == 0 ? 1 : encryptCost;
    cout.precision(2);
    cout << "[encryptPerformance] = " << fixed << repeatCount / ((double)encryptCost / 1000)
         << " tps" << endl;

    startTime = utcTime();
    for (auto i = 0; i < repeatCount; ++i)
    {
        crypto->sm4Decrypt(encryptedData, key);
    }
    endTime = utcTime();
    auto decrtyptCost = endTime - startTime;
    decrtyptCost = decrtyptCost == 0 ? 1 : decrtyptCost;
    cout << "[decryptPerformance] = " << fixed << repeatCount / ((double)decrtyptCost / 1000)
         << " tps" << endl;

    repeatCount = 100000;
    cout << "Testing sign/verify performance"
         << " ..." << endl;
    cout << "[repeatCount] = " << repeatCount << endl;
    auto keyPair = KeyPair::create();
    auto hash = sha3(dev::ref(asBytes(data)));

    h1024 signature;
    startTime = utcTime();
    for (auto i = 0; i < repeatCount; ++i)
    {
        signature = crypto->sign(keyPair.secret(), hash, keyPair.pub());
    }
    endTime = utcTime();
    auto signCost = endTime - startTime;
    cout << "[signPerformance] = " << repeatCount / ((double)signCost / 1000) << " tps" << endl;

    startTime = utcTime();
    for (auto i = 0; i < repeatCount; ++i)
    {
        crypto->verify(keyPair.pub(), signature, hash);
    }
    endTime = utcTime();
    auto verifyCost = endTime - startTime;
    cout << "[verifyPerformance] = " << repeatCount / ((double)verifyCost / 1000) << " tps" << endl;
    return 0;
}
