<?php

/**
 * Kolab 2-Factor-Authentication Webauthn driver implementation
 *
 * @author Bennet Becker <dev@bennet.cc>
 *
 * Copyright (C) 2025, Bennet Becker <dev@bennet.cc>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

namespace Kolab2FA\Driver;

use Ramsey\Uuid\Uuid;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;


class Webauthn extends Base
{
    public $method = 'webauthn';

    private SerializerInterface $serializer;
    private CeremonyStepManager $creationCSM;
    private CeremonyStepManager $requestCSM;

    /**
     *
     */
    public function init($config)
    {
        parent::init($config);

        $this->user_settings += [
            'registration_options' => [
                'type'      => 'text',
                'label'     => 'registration_options',
                'generator' => [$this, 'generate_registration_options'],
            ],
            'public_key_credential_source' => [
                'type'      => 'text',
                'private'   => true,
            ]
        ];

        $this->config += [
            "namespace_uuid" => Uuid::uuid5(Uuid::NAMESPACE_URL, $this->config["id"])->toString()
        ];

        $this->allowed_props += [
           "public_key_credential_source"
        ];

        $this->plugin->include_script('https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js');
        $this->plugin->include_script('webauthn.js');

        // attestation: The attestation data that is returned from the authenticator has information
        // that could be used to track users. This option allows servers to indicate how important
        // the attestation data is to this registration event. A value of "none" indicates that the
        // server does not care about attestation. A value of "indirect" means that the server will
        // allow for anonymized attestation data. direct means that the server wishes to receive the
        // attestation data from the authenticator. Read the spec.
        $attestationStatementSupportManager = AttestationStatementSupportManager::create();
        $attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());

        $factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
        $this->serializer = $factory->create();

        $csmFactory = new CeremonyStepManagerFactory();
        $csmFactory->setSecuredRelyingPartyId([$this->config["id"]]);
        $csmFactory->setAllowedOrigins($this->config["allowed_origins"]);

        $this->creationCSM = $csmFactory->creationCeremony();
        $this->requestCSM = $csmFactory->requestCeremony();
    }

    public function generate_registration_options()
    {
        $rcmail = \rcmail::get_instance();

        // RP (Relaying Party) Entity i.e. the application
        $rpEntity = PublicKeyCredentialRpEntity::create(
            $this->config['issuer'],
            $this->config['id'],
            $this->config['icon']
        );

//        error_log(json_encode($rcmail->user));

        // User Entity
        $userEntity = PublicKeyCredentialUserEntity::create(
            $rcmail->user->get_username(),
            Uuid::uuid5($this->config['namespace_uuid'], $rcmail->user->ID)->toString(), //ID
            $rcmail->user->get_identity()['name'], //Display name
            null //Icon
        );

        // Challenge
        $challenge = random_bytes(16);

        // authenticatorAttachment: This optional object helps relying parties make further restrictions
        // on the type of authenticators allowed for registration. In this example we are indicating we
        // want to register a cross-platform authenticator (like a Yubikey) instead of a platform
        // authenticator like Windows Hello or Touch ID. Read the spec.
        //
        // userVerification: The technical process by which an authenticator locally authorizes the
        // invocation of the authenticatorMakeCredential and authenticatorGetAssertion operations. User
        // verification MAY be instigated through various authorization gesture modalities; for example,
        // through a touch plus pin code, password entry, or biometric recognition (e.g., presenting a
        // fingerprint) [ISOBiometricVocabulary]. The intent is to distinguish individual users. See
        // https://w3c.github.io/webauthn/#user-verification
        //
        // residentKey: Specifies the extent to which the Relying Party desires to create a client-side
        // discoverable credential. For historical reasons the naming retains the deprecated “resident”
        // terminology. The value SHOULD be a member of ResidentKeyRequirement but client platforms MUST
        // ignore unknown values, treating an unknown value as if the member does not exist. If no value
        // is given then the effective value is required if requireResidentKey is true or discouraged if
        // it is false or absent.
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            residentKey:AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        );

        $publicKeyCredentialCreationOptions =
            PublicKeyCredentialCreationOptions::create(
                $rpEntity,
                $userEntity,
                $challenge,
                authenticatorSelection: $authenticatorSelectionCriteria
            );

        // The serializer is the same as the one created in the previous pages
        $jsonObject = $this->serializer->serialize(
            $publicKeyCredentialCreationOptions,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true, // Highly recommended!
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, // Optional
            ]
        );

        $rcmail->session->append("plugins.kolab2fa.webauthn", "public_key_credential_creation_options", $jsonObject);
//        $rcmail->session->append("plugins.kolab2fa.webauthn", "user_entity", $this->serializer->serialize($userEntity, 'json'));

        return $jsonObject;
    }

    /**
     *
     */
    public function verify($code, $timestamp = null)
    {
        error_log("Webauthn::verify() was called");
        //normal user authorization
        return true;
    }

    /**
     * @override
     */
    public function set($key, $value, $persistent = true)
    {
        $rcmail = \rcmail::get_instance();

        error_log("Webauthn::set() was called");
        if ($key == 'creation_response') {
            // Response Verification
            error_log('Webauthn::set() creation_response '. json_encode([$key, $value]));

            $publicKeyCredential = $this->serializer->deserialize(
                $value,
                PublicKeyCredential::class,
                'json'
            );


            if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
                //e.g. process here with a redirection to the public key creation page.
                //TODO
                return false;
            }

            $publicKeyCredentialCreationOptions = $this->serializer->deserialize(
                $_SESSION['plugins']['kolab2fa']['webauthn']['public_key_credential_creation_options'],
                PublicKeyCredentialCreationOptions::class,
                'json'
            );


            $authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
                $this->creationCSM
            );

            $publicKeyCredentialSource = $authenticatorAttestationResponseValidator->check(
                $publicKeyCredential->response,
                $publicKeyCredentialCreationOptions,
                $this->config['id']
            );

            // user data to persist
            $key = "public_key_credential_source";
            $value = $this->serializer->serialize($publicKeyCredentialSource, 'json');
            error_log("Webauthn::set() ".json_encode([$key, $value]));
        }

        return parent::set($key, $value, $persistent);
    }

    /**
     * @override
     */
    protected function set_user_prop($key, $value)
    {
        // set created timestamp
        if ($key !== 'created' && !isset($this->created)) {
            parent::set_user_prop('created', $this->get('created', true));
        }

        return parent::set_user_prop($key, $value);
    }
}
