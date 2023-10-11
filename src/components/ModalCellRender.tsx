import React, { useState } from 'react';
import Modal from 'react-modal';

interface ModalCellRendererProps {
  isModalOpen: boolean;
  setIsModalOpen: React.Dispatch<React.SetStateAction<boolean>>;
  closeModal: () => void;
  modalData?: string[];
}

Modal.setAppElement('#root');

const customStyles = {
  content: {
    top: '50%',
    left: '50%',
    right: 'auto',
    bottom: 'auto',
    marginRight: '-50%',
    transform: 'translate(-50%, -50%)',
  },
};

const ModalCellRenderer: React.FC<ModalCellRendererProps> = () => {
  const [isModalOpen, setIsModalOpen] = useState(false);

  const openModal = () => {
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
  };

  return (
    <div className='details-modal__container'>
      <button onClick={openModal}>View</button>
      {isModalOpen && (
        <Modal
          isOpen={isModalOpen}
          onRequestClose={closeModal}
          style={customStyles}
        >
          <button onClick={closeModal}>Close</button>
          <h2>Test Result Details</h2>
          {/* <p>ID: {modalData.id}</p>
            <p>Vulnerability: {modalData.vulnerability}</p>
            <p>Solution: {modalData.solution}</p> */}
          <p>Vulnerability: Boolean Based SQL Injection</p>
          <p>
            Solution: Have checks in place for GraphQL input. These checks
            validate that the input has an expected format and doesn’t include
            special characters frequently used in injection attacks. While input
            validation and sanitization can be performed in the resolvers
            (execution stage), it is recommended to do it earlier, in the
            validation stage, when the AST is validated against the GraphQL
            schema to determine that only valid types and fields are being
            requested. In addition to the basic Int, Float, String, Booleans,
            types, you can additionally enforce that inputs match custom scalar
            types, like email addresses. This helps you identify the data and
            validate it before even transferring it to the server.
          </p>
        </Modal>
      )}
    </div>
  );
};

export default ModalCellRenderer;
