package ghidra.app.plugin.core.analysis.tests;

import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class FakeProgram implements Program {
    DataTypeManager manager = new StandAloneDataTypeManager("root");

    /**
     * Get the listing object.
     *
     * @return the Listing interface to the listing object.
     */
    @Override
    public Listing getListing() {
        return null;
    }

    @Override
    public AddressMap getAddressMap() {
        return null;
    }

    /**
     * Returns the program's datatype manager.
     */
    @Override
    public DataTypeManager getDataTypeManager() {
        manager.startTransaction("Fake transaction");
        return manager;
    }

    /**
     * Returns the programs function manager.
     */
    @Override
    public FunctionManager getFunctionManager() {
        return null;
    }

    /**
     * Returns the user-specific data manager for
     * this program.
     */
    @Override
    public ProgramUserData getProgramUserData() {
        return null;
    }

    /**
     * Get the symbol table object.
     *
     * @return the symbol table object.
     */
    @Override
    public SymbolTable getSymbolTable() {
        return null;
    }

    /**
     * Returns the external manager.
     */
    @Override
    public ExternalManager getExternalManager() {
        return null;
    }

    /**
     * Get the equate table object.
     *
     * @return the equate table.
     */
    @Override
    public EquateTable getEquateTable() {
        return null;
    }

    /**
     * Get the memory object.
     *
     * @return the memory object.
     */
    @Override
    public Memory getMemory() {
        return null;
    }

    /**
     * Get the reference manager.
     */
    @Override
    public ReferenceManager getReferenceManager() {
        return null;
    }

    /**
     * Get the bookmark manager.
     */
    @Override
    public BookmarkManager getBookmarkManager() {
        return null;
    }

    /**
     * Gets the default pointer size in bytes as it may be stored within the program listing.
     *
     * @return default pointer size.
     * @see DataOrganization#getPointerSize()
     */
    @Override
    public int getDefaultPointerSize() {
        return 0;
    }

    /**
     * Gets the name of the compiler believed to have been used to create this program.
     * If the compiler hasn't been determined then "unknown" is returned.
     *
     * @return name of the compiler or "unknown".
     */
    @Override
    public String getCompiler() {
        return null;
    }

    /**
     * Sets the name of the compiler which created this program.
     *
     * @param compiler the name
     */
    @Override
    public void setCompiler(String compiler) {

    }

    /**
     * Gets the path to the program's executable file.
     * For example, <code>C:\Temp\test.exe</code>.
     * This will allow plugins to execute the program.
     *
     * @return String  path to program's exe file
     */
    @Override
    public String getExecutablePath() {
        return null;
    }

    /**
     * Sets the path to the program's executable file.
     * For example, <code>C:\Temp\test.exe</code>.
     *
     * @param path the path to the program's exe
     */
    @Override
    public void setExecutablePath(String path) {

    }

    /**
     * Returns a value corresponding to the original file format.
     */
    @Override
    public String getExecutableFormat() {
        return null;
    }

    /**
     * Sets the value corresponding to the original file format.
     *
     * @param format the format string to set.
     */
    @Override
    public void setExecutableFormat(String format) {

    }

    /**
     * Returns a value corresponding to the original binary file MD5 hash.
     * May be null if program source did not correspond to a binary file.
     */
    @Override
    public String getExecutableMD5() {
        return null;
    }

    /**
     * Sets the value corresponding to the original binary file MD5 hash.
     *
     * @param md5 MD5 binary file hash
     */
    @Override
    public void setExecutableMD5(String md5) {

    }

    /**
     * Returns the creation date of this program.
     * If the program was created before this property
     * existed, then Jan 1, 1970 is returned.
     *
     * @return the creation date of this program
     */
    @Override
    public Date getCreationDate() {
        return null;
    }

    /**
     * Gets the relocation table.
     */
    @Override
    public RelocationTable getRelocationTable() {
        return null;
    }

    /**
     * Returns the language used by this program.
     *
     * @return the language used by this program.
     */
    @Override
    public Language getLanguage() {
        return null;
    }

    /**
     * Returns the CompilerSpec currently used by this program.
     *
     * @return the compilerSpec currently used by this program.
     */
    @Override
    public CompilerSpec getCompilerSpec() {
        return null;
    }

    /**
     * Return the name of the language used by this program.
     *
     * @return the name of the language
     */
    @Override
    public LanguageID getLanguageID() {
        return null;
    }

    /**
     * Get the user propertyMangager stored with this program. The user property
     * manager is used to store arbitrary address indexed information associated
     * with the program.
     *
     * @return the user property manager.
     */
    @Override
    public PropertyMapManager getUsrPropertyManager() {
        return null;
    }

    /**
     * Returns the program context.
     */
    @Override
    public ProgramContext getProgramContext() {
        return null;
    }

    /**
     * get the program's minimum address.
     *
     * @return the program's minimum address or null if no memory blocks
     * have been defined in the program.
     */
    @Override
    public Address getMinAddress() {
        return null;
    }

    /**
     * Get the programs maximum address.
     *
     * @return the program's maximum address or null if no memory blocks
     * have been defined in the program.
     */
    @Override
    public Address getMaxAddress() {
        return null;
    }

    /**
     * Get the program changes since the last save as a set of addresses.
     *
     * @return set of changed addresses within program.
     */
    @Override
    public ProgramChangeSet getChanges() {
        return null;
    }

    /**
     * Returns the AddressFactory for this program.
     */
    @Override
    public AddressFactory getAddressFactory() {
        return null;
    }

    /**
     * Return an array of Addresses that could represent the given
     * string.
     *
     * @param addrStr the string to parse.
     * @return zero length array if addrStr is properly formatted but
     * no matching addresses were found or if the address is improperly formatted.
     */
    @Override
    public Address[] parseAddress(String addrStr) {
        return new Address[0];
    }

    /**
     * Return an array of Addresses that could represent the given
     * string.
     *
     * @param addrStr       the string to parse.
     * @param caseSensitive whether or not to process any addressSpace names as case sensitive.
     * @return zero length array if addrStr is properly formatted but
     * no matching addresses were found or if the address is improperly formatted.
     */
    @Override
    public Address[] parseAddress(String addrStr, boolean caseSensitive) {
        return new Address[0];
    }

    /**
     * Invalidates any caching in a program.
     * NOTE: Over-using this method can adversely affect system performance.
     */
    @Override
    public void invalidate() {

    }

    /**
     * Returns the register with the given name;
     *
     * @param name the name of the register to retrieve
     * @return register or null
     */
    @Override
    public Register getRegister(String name) {
        return null;
    }

    /**
     * Returns the largest register located at the specified address
     *
     * @param addr
     * @return largest register or null
     */
    @Override
    public Register getRegister(Address addr) {
        return null;
    }

    /**
     * Returns all registers located at the specified address
     *
     * @param addr
     * @return largest register
     */
    @Override
    public Register[] getRegisters(Address addr) {
        return new Register[0];
    }

    /**
     * Returns a specific register based upon its address and size
     *
     * @param addr register address
     * @param size the size of the register (in bytes);
     * @return register or null
     */
    @Override
    public Register getRegister(Address addr, int size) {
        return null;
    }

    /**
     * Returns the register which corresponds to the specified varnode
     *
     * @param varnode@return register or null
     */
    @Override
    public Register getRegister(Varnode varnode) {
        return null;
    }

    /**
     * Returns the current program image base address;
     */
    @Override
    public Address getImageBase() {
        return null;
    }

    /**
     * Sets the program's image base address.
     *
     * @param base   the new image base address;
     * @param commit if false, then the image base change is temporary and does not really change
     *               the program and will be lost once the program is closed.  If true, the change is permanent
     *               and marks the program as "changed" (needs saving).
     * @throws AddressOverflowException if the new image would cause a memory block to end past the
     *                                  the address space.
     * @throws LockException            if the program is shared and the user does not have an exclusive checkout.
     *                                  This will never be thrown if commit is false.
     * @throws IllegalStateException    if the program state is not suitable for setting the image base.
     */
    @Override
    public void setImageBase(Address base, boolean commit) throws AddressOverflowException, LockException, IllegalStateException {

    }

    /**
     * Restores the last committed image base.
     */
    @Override
    public void restoreImageBase() {

    }

    /**
     * Sets the language for the program. If the new language is "compatible" with the old language,
     * the addressMap is adjusted then the program is "re-disassembled".
     *
     * @param language           the new language to use.
     * @param compilerSpecID
     * @param forceRedisassembly if true a redisassembly will be forced.  This should always be false.
     * @param monitor            the task monitor
     * @throws IllegalStateException         thrown if any error occurs, including a cancelled monitor, which leaves this
     *                                       program object in an unusable state.  The current transaction should be aborted and the program instance
     *                                       discarded.
     * @throws IncompatibleLanguageException thrown if the new language is too different from the
     *                                       existing language.
     * @throws LockException                 if the program is shared and not checked out exclusively.
     */
    @Override
    public void setLanguage(Language language, CompilerSpecID compilerSpecID, boolean forceRedisassembly, TaskMonitor monitor) throws IllegalStateException, IncompatibleLanguageException, LockException {

    }

    /**
     * Returns the global namespace for this program
     */
    @Override
    public Namespace getGlobalNamespace() {
        return null;
    }

    /**
     * Create a new AddressSetPropertyMap with the specified name.
     *
     * @param name name of the property map.
     * @return the newly created property map.
     * @throws DuplicateNameException if a property map already exists with the given name.
     */
    @Override
    public AddressSetPropertyMap createAddressSetPropertyMap(String name) throws DuplicateNameException {
        return null;
    }

    /**
     * Create a new IntRangeMap with the specified name.
     *
     * @param name name of the property map.
     * @return the newly created property map.
     * @throws DuplicateNameException if a property map already exists with the given name.
     */
    @Override
    public IntRangeMap createIntRangeMap(String name) throws DuplicateNameException {
        return null;
    }

    /**
     * Get the property map with the given name.
     *
     * @param name name of the property map
     * @return null if no property map exist with the given name
     */
    @Override
    public AddressSetPropertyMap getAddressSetPropertyMap(String name) {
        return null;
    }

    /**
     * Get the property map with the given name.
     *
     * @param name name of the property map
     * @return null if no property map exist with the given name
     */
    @Override
    public IntRangeMap getIntRangeMap(String name) {
        return null;
    }

    /**
     * Remove the property map from the program.
     *
     * @param name name of the property map to remove
     */
    @Override
    public void deleteAddressSetPropertyMap(String name) {

    }

    /**
     * Remove the property map from the program.
     *
     * @param name name of the property map to remove
     */
    @Override
    public void deleteIntRangeMap(String name) {

    }

    /**
     * Returns an ID that is unique for this program.  This provides an easy way to store
     * references to a program across client persistence.
     */
    @Override
    public long getUniqueProgramID() {
        return 0;
    }

    /**
     * Start a new transaction in order to make changes to this domain object.
     * All changes must be made in the context of a transaction.
     * If a transaction is already in progress, a sub-transaction
     * of the current transaction will be returned.
     *
     * @param description brief description of transaction
     * @return transaction ID
     * @throws DomainObjectLockedException    the domain object is currently locked
     * @throws TerminatedTransactionException an existing transaction which has not yet ended was terminated early.
     *                                        Sub-transactions are not permitted until the terminated transaction ends.
     */
    @Override
    public int startTransaction(String description) {
        return 0;
    }

    /**
     * Start a new transaction in order to make changes to this domain object.
     * All changes must be made in the context of a transaction.
     * If a transaction is already in progress, a sub-transaction
     * of the current transaction will be returned.
     *
     * @param description brief description of transaction
     * @param listener    listener to be notified if the transaction is aborted.
     * @return transaction ID
     * @throws DomainObjectLockedException    the domain object is currently locked
     * @throws TerminatedTransactionException an existing transaction which has not yet ended was terminated early.
     *                                        Sub-transactions are not permitted until the terminated transaction ends.
     */
    @Override
    public int startTransaction(String description, AbortedTransactionListener listener) {
        return 0;
    }

    /**
     * Terminate the specified transaction for this domain object.
     *
     * @param transactionID transaction ID obtained from startTransaction method
     * @param commit        if true the changes made in this transaction will be marked for commit,
     */
    @Override
    public void endTransaction(int transactionID, boolean commit) {

    }

    /**
     * Returns the current transaction
     *
     * @return the current transaction
     */
    @Override
    public Transaction getCurrentTransaction() {
        return null;
    }

    /**
     * Returns true if the last transaction was terminated externally from the action that
     * started it.
     */
    @Override
    public boolean hasTerminatedTransaction() {
        return false;
    }

    /**
     * Return array of all domain objects synchronized with a
     * shared transaction manager.
     *
     * @return returns array of synchronized domain objects or
     * null if this domain object is not synchronized with others.
     */
    @Override
    public DomainObject[] getSynchronizedDomainObjects() {
        return new DomainObject[0];
    }

    /**
     * Synchronize the specified domain object with this domain object
     * using a shared transaction manager.  If either or both is already shared,
     * a transition to a single shared transaction manager will be
     * performed.
     *
     * @param domainObj
     * @throws LockException if lock or open transaction is active on either
     *                       this or the specified domain object
     */
    @Override
    public void addSynchronizedDomainObject(DomainObject domainObj) throws LockException {

    }

    /**
     * Remove this domain object from a shared transaction manager.  If
     * this object has not been synchronized with others via a shared
     * transaction manager, this method will have no affect.
     *
     * @throws LockException if lock or open transaction is active
     */
    @Override
    public void releaseSynchronizedDomainObject() throws LockException {

    }

    /**
     * Returns whether the object has changed.
     */
    @Override
    public boolean isChanged() {
        return false;
    }

    /**
     * Set the temporary state of this object.
     * If this object is temporary, the isChanged() method will
     * always return false.  The default temporary state is false.
     *
     * @param state if true object is marked as temporary
     */
    @Override
    public void setTemporary(boolean state) {

    }

    /**
     * Returns true if this object has been marked as Temporary.
     */
    @Override
    public boolean isTemporary() {
        return false;
    }

    /**
     * Returns true if changes are permitted.
     */
    @Override
    public boolean isChangeable() {
        return false;
    }

    /**
     * Returns true if this object can be saved; a read-only file
     * cannot be saved.
     */
    @Override
    public boolean canSave() {
        return false;
    }

    /**
     * Saves changes to the DomainFile.
     *
     * @param comment comment used for new version
     * @param monitor monitor that shows the progress of the save
     * @throws IOException        thrown if there was an error accessing this
     *                            domain object
     * @throws ReadOnlyException  thrown if this DomainObject is read only
     *                            and cannot be saved
     * @throws CancelledException thrown if the user canceled the save
     *                            operation
     */
    @Override
    public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {

    }

    /**
     * Saves (i.e., serializes) the current content to a packed file.
     *
     * @param outputFile packed output file
     * @param monitor    progress monitor
     * @throws IOException
     * @throws CancelledException
     * @throws UnsupportedOperationException if not supported by object implementation
     */
    @Override
    public void saveToPackedFile(File outputFile, TaskMonitor monitor) throws IOException, CancelledException {

    }

    /**
     * Notify the domain object that the specified consumer is no longer using it.
     * When the last consumer invokes this method, the domain object will be closed
     * and will become invalid.
     *
     * @param consumer the consumer (e.g., tool, plugin, etc) of the domain object
     *                 previously established with the addConsumer method.
     */
    @Override
    public void release(Object consumer) {

    }

    /**
     * Adds a listener for this object.
     *
     * @param dol listener notified when any change occurs to this domain object
     */
    @Override
    public void addListener(DomainObjectListener dol) {

    }

    /**
     * Remove the listener for this object.
     *
     * @param dol listener
     */
    @Override
    public void removeListener(DomainObjectListener dol) {

    }

    /**
     * Adds a listener that will be notified when this DomainObject is closed.  This is meant
     * for clients to have a chance to cleanup, such as reference removal.
     *
     * @param listener the reference to add
     */
    @Override
    public void addCloseListener(DomainObjectClosedListener listener) {

    }

    /**
     * Removes the given close listener.
     *
     * @param listener the listener to remove.
     */
    @Override
    public void removeCloseListener(DomainObjectClosedListener listener) {

    }

    /**
     * Creates a private event queue that can be flushed independently from the main event queue.
     *
     * @param listener the listener to be notified of domain object events.
     * @param maxDelay the time interval (in milliseconds) used to buffer events.
     * @return a unique identifier for this private queue.
     */
    @Override
    public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
        return null;
    }

    /**
     * Removes the specified private event queue
     *
     * @param id the id of the queue to remove.
     * @return true if the id represents a valid queue that was removed.
     */
    @Override
    public boolean removePrivateEventQueue(EventQueueID id) {
        return false;
    }

    /**
     * Returns a word or short phrase that best describes or categorizes
     * the object in terms that a user will understand.
     */
    @Override
    public String getDescription() {
        return null;
    }

    /**
     * Get the name of this domain object.
     */
    @Override
    public String getName() {
        return null;
    }

    /**
     * Set the name for this domain object.
     *
     * @param name object name
     */
    @Override
    public void setName(String name) {

    }

    /**
     * Get the domain file for this domain object.
     *
     * @return the associated domain file
     */
    @Override
    public DomainFile getDomainFile() {
        return null;
    }

    /**
     * Adds the given object as a consumer.  The release method must be invoked
     * with this same consumer instance when this domain object is no longer in-use.
     *
     * @param consumer domain object consumer
     * @return false if this domain object has already been closed
     */
    @Override
    public boolean addConsumer(Object consumer) {
        return false;
    }

    /**
     * Returns the list of consumers on this domainObject
     *
     * @return the list of consumers.
     */
    @Override
    public ArrayList<Object> getConsumerList() {
        return null;
    }

    /**
     * Returns true if the given consumer is using (has open) this domain object.
     *
     * @param consumer the object to test to see if it is a consumer of this domain object.
     * @return true if the given consumer is using (has open) this domain object;
     */
    @Override
    public boolean isUsedBy(Object consumer) {
        return false;
    }

    /**
     * If true, domain object change events are sent. If false, no events are sent.
     * <p>
     * <b>
     * NOTE: disabling events could cause plugins to be out of sync!
     * </b>
     * <p>
     * NOTE: when re-enabling events, an event will be sent to the system to signal that
     * every listener should update.
     *
     * @param enabled true means to enable events
     */
    @Override
    public void setEventsEnabled(boolean enabled) {

    }

    /**
     * Returns true if this object is sending out events as it is changed.  The default is
     * true.  You can change this value by calling {@link #setEventsEnabled(boolean)}.
     *
     * @see #setEventsEnabled(boolean)
     */
    @Override
    public boolean isSendingEvents() {
        return false;
    }

    /**
     * Makes sure all pending domainEvents have been sent.
     */
    @Override
    public void flushEvents() {

    }

    /**
     * Flush events from the specified event queue.
     *
     * @param id the id specifying the event queue to be flushed.
     */
    @Override
    public void flushPrivateEventQueue(EventQueueID id) {

    }

    /**
     * Returns true if a modification lock can be obtained on this
     * domain object.  Care should be taken with using this method since
     * this will not prevent another thread from modifying the domain object.
     */
    @Override
    public boolean canLock() {
        return false;
    }

    /**
     * Returns true if the domain object currenly has a modification lock enabled.
     */
    @Override
    public boolean isLocked() {
        return false;
    }

    /**
     * Attempt to obtain a modification lock on the domain object.  Multiple locks
     * may be granted on this domain object, although all lock owners must release their
     * lock in a timely fashion.
     *
     * @param reason very short reason for requesting lock
     * @return true if lock obtained successfully, else false which indicates that a
     * modification is in process.
     */
    @Override
    public boolean lock(String reason) {
        return false;
    }

    /**
     * Cancels any previous lock and aquires it.
     *
     * @param rollback if true, any changes in made with the previous lock should be discarded.
     * @param reason   very short reason for requesting lock
     */
    @Override
    public void forceLock(boolean rollback, String reason) {

    }

    /**
     * Release a modification lock previously granted with the lock method.
     */
    @Override
    public void unlock() {

    }

    /**
     * Returns all properties lists contained by this domain object.
     *
     * @return all property lists contained by this domain object.
     */
    @Override
    public List<String> getOptionsNames() {
        return null;
    }

    /**
     * Get the property list for the given name.
     *
     * @param propertyListName name of property list
     */
    @Override
    public Options getOptions(String propertyListName) {
        return new ToolOptions("tool");
    }

    /**
     * Returns true if this domain object has been closed as a result of the last release
     */
    @Override
    public boolean isClosed() {
        return false;
    }

    /**
     * Returns true if the user has exclusive access to the domain object.  Exclusive access means
     * either the object is not shared or the user has an exclusive checkout on the object.
     */
    @Override
    public boolean hasExclusiveAccess() {
        return false;
    }

    /**
     * Returns a map containing all the stored metadata associated with this domain object.  The map
     * contains key,value pairs and are ordered by their insertion order.
     *
     * @return a map containing all the stored metadata associated with this domain object.
     */
    @Override
    public Map<String, String> getMetadata() {
        return null;
    }

    /**
     * Returns a long value that gets incremented every time a change, undo, or redo takes place.
     * Useful for implementing a lazy caching system.
     *
     * @return a long value that is incremented for every change to the program.
     */
    @Override
    public long getModificationNumber() {
        return 0;
    }

    /**
     * Returns true if there is a previous state to "undo" to.
     */
    @Override
    public boolean canUndo() {
        return false;
    }

    /**
     * Returns true if there is a later state to "redo" to.
     */
    @Override
    public boolean canRedo() {
        return false;
    }

    /**
     * Clear all undoable/redoable transactions
     */
    @Override
    public void clearUndo() {

    }

    /**
     * Returns to the previous state.  Normally, this will cause the current state
     * to appear on the "redo" stack.  This method will do nothing if there are
     * no previous states to "undo".
     *
     * @throws IOException if an IO error occurs
     */
    @Override
    public void undo() throws IOException {

    }

    /**
     * Returns to a latter state that exists because of an undo.  Normally, this
     * will cause the current state to appear on the "undo" stack.  This method
     * will do nothing if there are no latter states to "redo".
     *
     * @throws IOException if an IO error occurs
     */
    @Override
    public void redo() throws IOException {

    }

    /**
     * Returns a description of the chanage that would be "undone".
     */
    @Override
    public String getUndoName() {
        return null;
    }

    /**
     * Returns a description of the change that would be "redone".
     */
    @Override
    public String getRedoName() {
        return null;
    }

    /**
     * Adds the given transaction listener to this domain object
     *
     * @param listener the new transaction listener to add
     */
    @Override
    public void addTransactionListener(TransactionListener listener) {

    }

    /**
     * Removes the given transaction listener from this domain object.
     *
     * @param listener the transaction listener to remove
     */
    @Override
    public void removeTransactionListener(TransactionListener listener) {

    }
}
