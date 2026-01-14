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

use html_inputfield;
use Ramsey\Uuid\Uuid;
use Random\RandomException;
use rcmail;
use rcube;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;



class Webauthn extends DriverBase
{
    public string $method = 'webauthn';

    private SerializerInterface $serializer;
    private CeremonyStepManager $creationCSM;
    private CeremonyStepManager $requestCSM;

    /**
     *
     */
    public function init($config): void
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

        if (empty($this->config["authenticator_selection_criteria"])) {
            $this->config["authenticator_selection_criteria"] = [
                'authenticator_attachment' => null,
                'user_verification' => 'preferred',
                'resident_key' => 'preferred'
            ];
        }

        if ($this->config["authenticator_selection_criteria"]["authenticator_attachment"] == 'no-preference' ||
            !in_array($this->config["authenticator_selection_criteria"]["authenticator_attachment"],
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENTS)) {
            $this->config["authenticator_selection_criteria"]["authenticator_attachment"] = null;
        }

        if ($this->config["authenticator_selection_criteria"]["resident_key"] == 'no-preference') {
            $this->config["authenticator_selection_criteria"]["resident_key"] = null;
        }

        if (!in_array($this->config["authenticator_selection_criteria"]["resident_key"],
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENTS)) {
            $this->config["authenticator_selection_criteria"]["resident_key"] = 'preferred';
        }

        if (!in_array($this->config["authenticator_selection_criteria"]["user_verification"],
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENTS)) {
            $this->config["authenticator_selection_criteria"]["user_verification"] = 'preferred';
        }

        $this->allowed_props += [
           "public_key_credential_source"
        ];

        if ($this->temporary) {
            if (array_key_exists("browser_script", $this->config) &&
                $this->config["browser_script"] == 'lastest_remote') {

                $this->plugin->include_script('https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js');
            } else {
                $this->plugin->include_script('simplewebauthn_browser_13.2.2_index.umd.min.js');
            }
            $this->plugin->include_script('webauthn.js');
        }

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

    /**
     * Generate the Registration data to add authenticator
     * Called from settings
     *
     * @return string
     * @throws RandomException when system is broken
     * @throws ExceptionInterface when serialization failed
     */
    public function generate_registration_options(): string
    {
        $rcmail = rcmail::get_instance();

        // RP (Relaying Party) Entity i.e. the application
        $rpEntity = PublicKeyCredentialRpEntity::create(
            $this->config['issuer'],
            $this->config['id'],
            $this->config['icon']
        );

        // User Entity
        $userEntity = PublicKeyCredentialUserEntity::create(
            $rcmail->user->get_username(),
            Uuid::uuid5($this->config['namespace_uuid'], $rcmail->user->ID)->toString(), //ID
            $rcmail->user->get_identity()['name'], //Display name
        );

        // Challenge
        $challenge = random_bytes(16);

        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: $this->config["authenticator_selection_criteria"]["authenticator_attachment"],
            userVerification: $this->config["authenticator_selection_criteria"]["user_verification"],
            residentKey: $this->config["authenticator_selection_criteria"]["resident_key"],
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

        $_SESSION['kolab_2fa_webauthn'] = [
            ...($_SESSION['kolab_2fa_webauthn'] ?? []),
            "public_key_credential_creation_options"=> $jsonObject
        ];

        return $jsonObject;
    }

    /**
     * Return Input field with Authentication data
     * @throws RandomException
     * @throws \Exception
     */
    public function login_input(string $name, string $field_id, array $attrib, ?bool $required = false) : ?html_inputfield
    {
        //$rcmail = rcmail::get_instance();
        $me = $this;
        $allowedCredentials = array_values(array_filter(array_map(
            static function (string $factor) use ($me) {
                [$method] = explode(':', $factor, 2);
                if ($method === 'webauthn') {
                    $driver = new self($me->plugin, $me->plugin->get_storage(), $me->config, $factor);
                    /**
                     * @var $publicKeyCredentialSource PublicKeyCredentialSource
                     */
                    try {
                        $publicKeyCredentialSource = $me->serializer->deserialize(
                            $driver->get('public_key_credential_source'),
                            PublicKeyCredentialSource::class,
                            'json');
                    } catch (ExceptionInterface) {
                        return null;
                    }
                    return $publicKeyCredentialSource->getPublicKeyCredentialDescriptor();
                }
                return null;
            },
            $this->plugin->get_storage()->enumerate() //TODO: factor may be provided by other plugin
        )));

        // Public Key Credential Request Options
        $publicKeyCredentialRequestOptions =
            PublicKeyCredentialRequestOptions::create(
                random_bytes(32), // Challenge
                allowCredentials: $allowedCredentials,
                userVerification: $this->config["authenticator_selection_criteria"]["user_verification"]
            )
        ;

        try {
            $authOptions = $this->serializer->serialize($publicKeyCredentialRequestOptions, 'json');
            $_SESSION['kolab_2fa_webauthn'] = [
                ...($_SESSION['kolab_2fa_webauthn'] ?? []),
                "public_key_credential_creation_options" => $authOptions
            ];

            return new html_inputfield([
                    'name' => $name,
                    'class' => 'kolab2facode',
                    'id' => $field_id,
                    'required' => $required,
                    'autocomplete' => 'off',
                    'data-icon' => 'key', // for Elastic
                    'aria-auth-options' => base64_encode($authOptions)
                ] + $attrib);
        } catch (ExceptionInterface) {
            return null;
        }
    }

    /**
     * Authenticate the WebAuthN request during Login
     *
     * @throws \Exception when loading data failed
     */
    public function verify(string $code, int $timestamp = null): bool
    {
        $rcmail = rcmail::get_instance();
        error_log("Webauthn::verify() was called: ". $code);
        //normal user authorization

        try {
            // Response from Device
            $publicKeyCredential = $this->serializer->deserialize($code, PublicKeyCredential::class, 'json');
        } catch (ExceptionInterface) {
            $publicKeyCredential = null;
        } finally {
            if (is_null($publicKeyCredential) || !$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
                //e.g. process here with a redirection to the public key login/MFA page.
                rcube::raise_error("Invalid Authenticator Assertion Response", true);
                return false;
            }
        }

        try {
            // Created during registration (updated on authentication)
            $publicKeyCredentialSource = $this->serializer->deserialize($this->get('public_key_credential_source'), PublicKeyCredentialSource::class, 'json');
        } catch (ExceptionInterface) {
            $publicKeyCredentialSource = null;
        } finally {
            if ($publicKeyCredentialSource === null) {
                // Throw an exception if the credential is not found.
                // It can also be rejected depending on your security policy (e.g. disabled by the user because of loss)
                rcube::raise_error("Invalid Data in User Profile.", true);
                return false;
            }
        }

        try {
            // Created previously for authentication
            $publicKeyCredentialRequestOptions = $this->serializer->deserialize(
                $_SESSION["kolab_2fa_webauthn"]["public_key_credential_creation_options"],
                PublicKeyCredentialRequestOptions::class,
                'json');
            // Can't reset session yet. we might want to check multiple authenticators
            // unset($_SESSION["kolab_2fa_webauthn"]["public_key_credential_creation_options"]);
        } catch (ExceptionInterface) {
            $publicKeyCredentialRequestOptions = null;
        } finally {
            if ($publicKeyCredentialRequestOptions === null) {
                // Throw an exception if the credential is not found.
                // It can also be rejected depending on your security policy (e.g. disabled by the user because of loss)
                rcube::raise_error("Invalid Session Data.", true);
                unset($_SESSION["kolab_2fa_webauthn"]["public_key_credential_creation_options"]);
                return false;
            }
        }

        $authenticatorAssertionResponseValidator = AuthenticatorAssertionResponseValidator::create(
            $this->requestCSM
        );

        try {
            $publicKeyCredentialSource = $authenticatorAssertionResponseValidator->check(
                $publicKeyCredentialSource,
                $publicKeyCredential->response,
                $publicKeyCredentialRequestOptions,
                $this->config['id'],
                $rcmail->user->ID ? Uuid::uuid5($this->config['namespace_uuid'], $rcmail->user->ID)->toString() : null
            );

            $this->set('public_key_credential_source',$this->serializer->serialize($publicKeyCredentialSource, 'json'));
        } catch (AuthenticatorResponseVerificationException $e) {
            error_log("Webauthn::verify() failed: ". $e->getMessage());
            return false;
        } catch (ExceptionInterface $e) {
            rcube::raise_error($e, true);
            unset($_SESSION["kolab_2fa_webauthn"]["public_key_credential_creation_options"]);
            return true;
        }

        unset($_SESSION["kolab_2fa_webauthn"]["public_key_credential_creation_options"]);
        return true;
    }

    /**
     * @override
     * @throws \Exception on data errors
     */
    public function set($key, $value, $persistent = true): bool
    {
        if ($key == 'creation_response') {
            // Verify the registration response

            try {
                // Response form the device
                $publicKeyCredential = $this->serializer->deserialize(
                    $value,
                    PublicKeyCredential::class,
                    'json'
                );
            } catch (ExceptionInterface) {
                $publicKeyCredential = null;
            } finally {
                if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
                    //e.g. process here with a redirection to the public key creation page.
                    rcube::raise_error("Invalid Authenticator Assertion Response", true);
                    return false;
                }
            }

            try {
                // Created previously for registration
                $publicKeyCredentialCreationOptions = $this->serializer->deserialize(
                    $_SESSION['kolab_2fa_webauthn']['public_key_credential_creation_options'],
                    PublicKeyCredentialCreationOptions::class,
                    'json'
                );
                unset($_SESSION['kolab_2fa_webauthn']['public_key_credential_creation_options']);
            } catch (ExceptionInterface) {
                rcube::raise_error("Invalid Session Data", true);
                return false;
            }

            $authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
                $this->creationCSM
            );

            try {
                $publicKeyCredentialSource = $authenticatorAttestationResponseValidator->check(
                    $publicKeyCredential->response,
                    $publicKeyCredentialCreationOptions,
                    $this->config['id']
                );
            } catch (Throwable) {
                rcube::raise_error("Invalid Authenticator Data", true);
                return false;
            }

            try {
                // user data to persist
                $key = "public_key_credential_source";
                $value = $this->serializer->serialize($publicKeyCredentialSource, 'json');
            } catch (ExceptionInterface) {
                rcube::raise_error("Failed to save data", true);
                return false;
            }
        }

        return parent::set($key, $value, $persistent);
    }

    /**
     * @override
     */
    protected function set_user_prop($key, $value): bool
    {
        // set created timestamp
        if ($key !== 'created' && !isset($this->created)) {
            parent::set_user_prop('created', $this->get('created', true));
        }

        return parent::set_user_prop($key, $value);
    }
}
