/*
 * (C) 2014-2017 Jack Lloyd
 *     2017      Falko Strenzke, cryptosource GmbH
 *
 * Botan and the TLS Test Tool are released under the Simplified BSD License (see license.txt)
 */

#ifndef __cred_man__H_
#define __cred_man__H_

#include <botan/pkcs8.h>
#include <botan/credentials_manager.h>
#include <botan/x509self.h>
#include <iostream>
#include <fstream>
#include <memory>

class Cert_Path_Credentials_Manager : public Botan::Credentials_Manager
   {
   public:
      Cert_Path_Credentials_Manager()
         {
         //load_certstores();
         }

      Cert_Path_Credentials_Manager(Botan::RandomNumberGenerator& rng,
                                const std::string& server_crt,
                                const std::string& server_key,
                                Botan::X509_Certificate* trusted_root
                                )
      {
        Certificate_Info cert;

        cert.key.reset(Botan::PKCS8::load_key(server_key, rng));

        Botan::DataSource_Stream in(server_crt);
        while(!in.end_of_data())
        {
          try
          {
            cert.certs.push_back(Botan::X509_Certificate(in));
          }
          catch(std::exception& e)
          {

          }
        }
        
        m_creds.push_back(cert);

        if(trusted_root != nullptr)
        {
          auto sp_cs = std::shared_ptr<Botan::Certificate_Store>(new Botan::Certificate_Store_In_Memory());
          dynamic_cast<Botan::Certificate_Store_In_Memory*>(sp_cs.get())->add_certificate(*trusted_root);
          m_certstores.push_back(sp_cs);
        }
      }

      void load_certstores()
         {

           throw Botan::Invalid_Argument("load_certstores not supported");
         }

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string& /*type*/,
                                      const std::string& /*hostname*/) override
         {
         std::vector<Botan::Certificate_Store*> v;

         for(auto&& cs : m_certstores)
            v.push_back(cs.get());

         return v;
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& algos,
         const std::string& type,
         const std::string& hostname) override
         {
         BOTAN_UNUSED(type);

         for(auto&& i : m_creds)
            {
            if(std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end())
               continue;

            return i.certs;
            }

         return std::vector<Botan::X509_Certificate>();
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
                                          const std::string& /*type*/,
                                          const std::string& /*context*/) override
         {
         for(auto&& i : m_creds)
            {
            if(cert == i.certs[0])
               return i.key.get();
            }

         return nullptr;
         }

   private:
      struct Certificate_Info
         {
            std::vector<Botan::X509_Certificate> certs;
            std::shared_ptr<Botan::Private_Key> key;
         };

      std::vector<Certificate_Info> m_creds;
      std::vector<std::shared_ptr<Botan::Certificate_Store>> m_certstores;
   };


#endif /* h-guard */
