from components.base.ecu.software.abst_comm_layers import AbstractCommModule
from tools.general import RefList, General as G
from io_processing.surveillance_handler import MonitorInput, MonitorTags
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from components.base.ecu.software.impl_datalink_layers import StdDatalinkLayer
from components.base.ecu.software.impl_transport_layers import FakeSegmentTransportLayer,\
    SegmentTransportLayer
from tools.general import General as G
import uuid
from io_processing.surveillance_handler import MonitorInput, MonitorTags
from components.security.encryption import encryption_tools
from components.security.encryption.public_key_manager import PublicKeyManager
from enums.sec_cfg_enum import AsymAuthMechEnum, AuKeyLengthEnum, SymAuthMechEnum, HashMechEnum,\
    CAEnum
from components.base.message.abst_bus_message import SegData
from components.security.encryption.encryption_tools import HashedMessage
from config.specification_set import GeneralSpecPreset
from components.security.encryption.encryption_tools import compress, mac, MACKey, decompress, \
    certificate_trustworthy, sym_get_key, sym_encrypt, sym_decrypt, asy_decrypt, EncryptionSize
from config.timing_db_admin import TimingDBMap
from enums.sec_cfg_enum import EnumTrafor


class MyProtocolCommModule(AbstractCommModule):
    
    def __init__(self, sim_env, ecu_id):
        ''' Constructor
            
            Input:  ecu_id         string                   id of the corresponding AbstractECU
                    sim_env        simpy.Environment        environment of this component
            Output:  -
        '''
        AbstractCommModule.__init__(self, sim_env)

        # local parameters
        self._ecu_id = ecu_id
        self._jitter_in = 1
        self.monitor_list = RefList()
        self._have_session_key = False
        self._session_key = None
        
        # initialize
        self._init_layers(self.sim_env, self.MessageClass)
        
        # add tags
        self._tags = ["AUTH_SEND_TIME_BEFORE_ENCRYPTION", "AUTH_SEND_TIME_AFTER_ENCRYPTION", "AUTH_RECEIVE_TIME_BEFORE_DECRYPTION", "AUTH_RECEIVE_TIME_AFTER_DECRYPTION"]        
    
        # NEW: Add key pair - public and private
        assymetric_encryption_algorithm = AsymAuthMechEnum.RSA
        assymetric_encryption_key_length = AuKeyLengthEnum.bit_512
        assymetric_encryption_option = 65537
        self.priv_key, self.pub_key = encryption_tools.asy_get_key_pair(assymetric_encryption_algorithm, assymetric_encryption_key_length, assymetric_encryption_option)
        PublicKeyManager().add_key(self._ecu_id, self.pub_key) # make public key available to everybody

        # Create a certificate from root L3 along L3 L31 L311
        [certificate, root_certificates_to_verify_this_certificate, self.certificate_private_key] = GeneralSpecPreset().certificate_manager.generate_valid_ecu_cert(self._ecu_id, CAEnum.CA_L311, 0, float('inf'))
        self.my_certificate = certificate
        self.my_root_certificates = root_certificates_to_verify_this_certificate
         
        # verify certificate from root L311 with right root certificates
        #certificate_valid = encryption_tools.certificate_trustworthy(certificate, root_certificates_to_verify_this_certificate, self.sim_env.now)

    def _get_time_for_session_decryption(self, encrypted_message):
        """
        This method computes the decryption time (as an example) based on the input message size
        :return:
        """

        # decrypted size
        size_to_decrypt = 24

        # decryption time
        algorithm = EnumTrafor().to_value(SymAuthMechEnum.AES)
        key_len = EnumTrafor().to_value(AuKeyLengthEnum.bit_128)

        library_tag = "Crypto_Lib_HW"  # available tags: ['CyaSSL', 'Crypto_Lib_HW', 'Crypto_Lib_SW']

        db_val = TimingDBMap().lookup_interpol(lib=library_tag, mode='DECRYPTION', \
                                               keylen=key_len, alg=algorithm, data_size=size_to_decrypt,
                                               description='some_description')

        decrypted_size = encrypted_message.msg_unencrpyted._size  # this is stored in the encrypted message

        decryption_time = db_val

        return decryption_time, decrypted_size

    def _get_time_for_session_encryption(self, encrypted_message):
        '''
        This method computes the encryption time (as an example) based on the input message size

        Arguments for the lookup_interpol function are:
        --> Checkout the content of the database in ECUSimulation/config/data/measurements.db
        --> There you can also add your own measurements
        looks for a value in the database. If none is found looks for variables
                    around it and tries to interpolate a value from the neighboring values

                    Input:  lib        string            value of library column in the DB
                            mode       string            mode requested of library column in the DB e.g. ENCRYPTION, DECRYPTION,...
                            alg        string            name of the algorithm of library column in the DB
                            alg_mode   string            name of algorithm mode of library column in the DB (e.g. CTR, ...)
                            keylen     integer           length of the key in bit of library column in the DB
                            exp        integer           size of the exponent when RSA is used
                            param_len  integer           length of the parameter whenn ECC is used (library column in the DB )
                            data_size  integer           size of the data of library column in the DB
                            ret_all    boolean           if this value is true the values for all data_sizes will be returned
                    Output: time       float             interpolated time from requested values in the database
        '''

        # encrypted size
        size_to_encrypt = encrypted_message._size

        # encryption time
        algorithm = EnumTrafor().to_value(SymAuthMechEnum.AES)
        key_len = EnumTrafor().to_value(AuKeyLengthEnum.bit_128)

        library_tag = "Crypto_Lib_HW" # available tags: ['CyaSSL', 'Crypto_Lib_HW', 'Crypto_Lib_SW']

        db_val = TimingDBMap().lookup_interpol(lib=library_tag, mode='ENCRYPTION', \
                                               keylen=key_len, alg=algorithm, data_size=size_to_encrypt,
                                               description='t_ecu_auth_reg_msg_validate_cert')

        encrypted_size = 24 # something you need to compute yourself or use the examples provided in ECUSimulation/components/security/ecu/types/impl_sec_mod_lwa.py

        encryption_time = db_val

        return encryption_time, encrypted_size


    def receive_msg(self):
        
        while True:
                        
            # receive from lower layer
            [message_id, message_data] = yield self.sim_env.process(self.transp_lay.receive_msg())

            # receiver information    
            print("\n\nRECEIVER\nTime: "+str(self.sim_env.now)+"--Communication Layer: \nI am ECU " + self._ecu_id + "\nReceived message:\n - ID: " + str(message_id))

            # ALL PARTIES RECEIVED A SESSION KEY WE CAN DECRYPT THE MESSAGE HERE AND PASS IT TO THE
            # APPLICATION LAYER IF DECRYPTION WAS SUCCESSFUL
            if self._have_session_key and not message_id in [901, 902, 903]:
                # decryption
                decrypted_msg = sym_decrypt(message_data.get(), self._session_key)

                # compute decrypted time and size
                print("%s: Time before decryption %s" % (str(self._ecu_id), str(self.sim_env.now)))
                decryption_time, decrypted_size = self._get_time_for_session_decryption(message_data.get())
                yield self.sim_env.timeout(decryption_time) # time for decryption
                print("%s: Time after decryption %s" % (str(self._ecu_id), str(self.sim_env.now)))

                # if successful pass to app layer
                if decrypted_msg is None:
                    print("--- Decryption was not successful - probably this ECU did not get the session key")
                else:
                    message_data = decrypted_msg.get()
                    # push to higher layer
                    return [message_id, message_data]

            # PART 1 OF OUR SIMPLE PROTOCOL, THE PROTOCOL IS RECEIVED AND A SESSION-KEY IS GENERATED AND SEND
            # TO THE OTHER ECUS, ALSO THIS SESSION KEY IS STORED AND USED FOR THE REMAINING COMMUNICATION
            if message_id == 901:

                #receive and verify certificate
                [encrypted_msg, received_certificate, received_cert_private_key] = message_data.get()
                # verify certificate - which works here as they all have the same CA authority that signed the certificate
                certificate_valid = encryption_tools.certificate_trustworthy(received_certificate, self.my_root_certificates, self.sim_env.now)
                print("Certificate is valid? %s" % str(certificate_valid))

                # Encrypt the new message
                clear_message = asy_decrypt(encrypted_msg, received_cert_private_key, self.sim_env.now)
                print("Received CLEAR MESSAGE %s" % str(clear_message.get()))

                # Respond with a session key of size 30
                self._session_key = sym_get_key(SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128)
                self._have_session_key = True

                sec_message_id = 902
                yield self.sim_env.process(self.transp_lay.send_msg(self._ecu_id, sec_message_id, SegData(self._session_key, 30)))

            # RECEIVE A SESSION KEY AND STORE IT
            if message_id == 902:
                # Read the message data -> which is session key
                self._session_key = message_data.get()
                self._have_session_key = True # return a all good message with id 903 of size 20
                sec_message_id = 903


    def send_msg(self, sender_id, message_id, message):
        # Sender information

        # INITIALLY SEND MY CERTIFICATE TO THE OTHER ECU
        if not self._have_session_key:
            print("Sending Certificate and my private key : ")
            # Encrypt message with the public key
            encrypted_msg = encryption_tools.asy_encrypt(message, self.my_certificate.pub_key_user)

            # Send the certificate and message and private key
            message_to_send = SegData([encrypted_msg, self.my_certificate, self.certificate_private_key], 50)
            sec_message_id = 901
            print("\n\nSENDER - \nTime: " + str(
                self.sim_env.now) + "--Communication Layer: \nI am ECU " + sender_id + "\nSending message:\n - ID: " + str(
                sec_message_id) + "\n - Content: " + str(message_to_send.get()))
            yield self.sim_env.process(self.transp_lay.send_msg(sender_id, sec_message_id, message_to_send))


        else:
            # IF THE RECEIVE MSG FUNCTION STORED A SESSION KEY THIS KEY IS NOW USED TO ENCRYPT A MESSAGE
            # AND TO SEND THE ENCRYPTED MESSAGE

            # Encrypt message
            encrypted_msg = sym_encrypt(message, self._session_key)
            print("\n\nSENDER - \nTime: "+str(self.sim_env.now)+"--Communication Layer: \nI am ECU " + sender_id + "\nSending message:\n - ID: " + str(message_id)+"\n - Content: " + message.get())

            # Sending message now with the session key I have
            print("\nEncrypted the message")

            # Send message - here send your message with your message_id
            print("%s: Time before encryption %s" % (str(self._ecu_id), str(self.sim_env.now)))
            encryption_time, encrypted_size = self._get_time_for_session_encryption(message)
            yield self.sim_env.timeout(encryption_time) # apply time for encryption
            print("%s: Time after encryption %s"  % (str(self._ecu_id), str(self.sim_env.now)))

            yield self.sim_env.process(self.transp_lay.send_msg(sender_id, message_id, SegData(encrypted_msg, encrypted_size)))

            
    def _init_layers(self, sim_env, MessageClass):
        ''' Initializes the software layers 
            
            Input:  sim_env                        simpy.Environment        environment of this component                      
                    MessageClass                   AbstractBusMessage       class of the messages  how they are sent on the CAN Bus
            Output: -                   
        '''
        
        # create layers
        self.physical_lay = StdPhysicalLayer(sim_env)         
        self.datalink_lay = StdDatalinkLayer(sim_env) 
        self.transp_lay = SegmentTransportLayer(sim_env, MessageClass)
   
        # interconnect layers             
        self.datalink_lay.physical_lay = self.physical_lay        
        self.transp_lay.datalink_lay = self.datalink_lay           
        
        
    @property
    def ecu_id(self):
        return self._ecu_id
               
    @ecu_id.setter    
    def ecu_id(self, value):
        self._ecu_id = value          

    def monitor_update(self):
        ''' updates the monitor connected to this ecu
            
            Input:    -
            Output:   monitor_list    RefList    list of MonitorInputs
        '''
        # register Monitoring tags to track
        #G().register_eventline_tags(self._tags)
        
        items_1 = len(self.transp_lay.datalink_lay.controller.receive_buffer.items)
        items_2 = self.transp_lay.datalink_lay.transmit_buffer_size
        
        G().mon(self.monitor_list, MonitorInput(items_1, MonitorTags.BT_ECU_RECEIVE_BUFFER, self._ecu_id, self.sim_env.now))
        G().mon(self.monitor_list, MonitorInput(items_2, MonitorTags.BT_ECU_TRANSMIT_BUFFER, self._ecu_id, self.sim_env.now))
        
        self.monitor_list.clear_on_access()  # on the next access the list will be cleared        
        return self.monitor_list.get()

