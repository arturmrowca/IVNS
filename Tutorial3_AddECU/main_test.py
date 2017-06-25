#!/usr/bin/env python
import logging
import os
import api.ecu_sim_api as api
from components.base.gateways.impl_can_gateway import CANGateway  # @UnusedImport
from api.core.component_specs import RegularECUSpec, SimpleBusCouplerSpec, SimpleBusSpec
from io_processing.surveillance import Monitor
from io_processing.result_reader import ResultReader
from io_processing.result_interpreter.abst_result_interpreter import InterpreterOptions
from io_processing.result_interpreter.can_bus_interpreter import CanBusInterpreter
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from io_processing.result_interpreter.checkpoint_interpreter import CheckpointInterpreter
from io_processing.result_interpreter.buffer_interpreter import BufferInterpreter
from io_processing.surveillance_handler import InputHandlerChain, EventlineHandler  # @UnusedImport


#===============================================================================
#     -> Register folder with our new ECU
#     -> Setup logging
#     -> Create Environment
#===============================================================================
api.register_ecu_classes(os.path.join(os.path.dirname(__file__), "ecus"))

# setup the logging
api_log_path = os.path.join(os.path.dirname(__file__), "logs/api.log")
api.show_logging(logging.INFO, api_log_path, True)

# create an empty environment specification for the environment
sim_env = api.create_environment(200)

#===============================================================================
#     Creating ECUs
#=============================================================================== 
# create ECU with specification A
ecu_spec = RegularECUSpec(["My_Test_ECU_1"], 20000, 20000)
ecu_spec.add_sending_actions(2, 0.5, 16, "TEST STRING B", 50)  # sends a at time 10, 10.5, 11... message id 16, content test string b and size 50
ecu_group_1 = api.set_ecus(sim_env, 1, 'MyProtocolECU', ecu_spec)
 
# create 2 ECUs with specification B (here: same as A)
ecu_spec = RegularECUSpec(["My_Test_ECU_2", "My_Test_ECU_3"], 20000, 20000)
ecu_group_3 = api.set_ecus(sim_env, 2, 'MyProtocolECU', ecu_spec)

# create 3 ECUs with specification C (here: same as A)
ecu_spec = RegularECUSpec(["My_Test_ECU_4", "My_Test_ECU_5", "My_Test_ECU_6"], 20000, 20000)
ecu_group_4 = api.set_ecus(sim_env, 3, 'MyProtocolECU', ecu_spec)
 
#===============================================================================
#     Creating Gateways
#===============================================================================

# create the Gateway specification
ecu_spec = SimpleBusCouplerSpec([])

# set gateway delay to 0.000002 seconds
ecu_spec.set_ecu_setting('t_transition_process', 0.000002)

# create the gateway
gateway_group_1 = api.set_ecus(sim_env, 1, 'CANGateway', ecu_spec)

# create another gateway with same specification
gateway_group_2 = api.set_ecus(sim_env, 1, 'CANGateway', ecu_spec)

 
#===============================================================================
#     Create Architecture
#===============================================================================
 
# create the bus specifications
bus_spec = SimpleBusSpec(['CAN_0', 'CAN_1', 'CAN_2'])
bus_group = api.set_busses(sim_env, 3, 'StdCANBus', bus_spec)
 
# Connect ECUs and Gateways to the busses
# Connect CAN 0 via GW1 to CAN 1 // Connect CAN 1 via GW 2 to CAN 2
api.connect_bus_by_obj(sim_env, 'CAN_0', ecu_group_1  + gateway_group_1) 
api.connect_bus_by_obj(sim_env, 'CAN_1', gateway_group_1 + ecu_group_3 + gateway_group_2)
api.connect_bus_by_obj(sim_env, 'CAN_2', ecu_group_4 + gateway_group_2)
 
#===========================================================================
#     Monitoring and Export of Results
#
#    Structure:
#    environment connected to monitor object
#    monitor object connected to ResultReader object
#    ResultReader publishes data to the Interpreters
#    Interpreters pass the data to connected GUI and/or to Files
#===========================================================================

# create a Monitor and connect it to the environment
monitor = Monitor()
monitor.set_sample_time(0.48)
api.connect_monitor(sim_env, monitor, 0.5)  

# create a Result Reader that is used to export the 
# simulation results to the GUI or to a file
result_reader = ResultReader()
save_path_cp = os.path.join(os.path.dirname(__file__), "logs/checkpoints.csv")
save_path_buf = os.path.join(os.path.dirname(__file__), "logs/buffer.csv")
save_path_can = os.path.join(os.path.dirname(__file__), "logs/can_bus.csv")

# enable certain handlers to define which export has to be made
# a result reader receives the interpreter to be used and the InterpreterOptions enum
# defining how the export should be performed
result_reader.enable_handler(BufferInterpreter, [InterpreterOptions.CONNECTION, InterpreterOptions.CSV_FILE], save_path_buf) 
result_reader.enable_handler(CheckpointInterpreter, [ InterpreterOptions.TIMING_FILE], save_path_cp)
result_reader.enable_handler(EventlineInterpreter, [InterpreterOptions.CSV_FILE], save_path_cp)  # CSV Live Tracking
result_reader.enable_handler(CanBusInterpreter, [InterpreterOptions.CSV_MSG_FILE, InterpreterOptions.CSV_DR_FILE], save_path_can)

# connect the result reader to the monitor
api.connect_result_reader(sim_env, monitor, result_reader)


#===========================================================================
#     Build and run simulation
#===========================================================================

# run the simulation
api.build_simulation(sim_env)
api.run_simulation(sim_env)

