// See the file "COPYING" in the main distribution directory for copyright.

// Subclasses of Func and Stmt to support C++-generated code, along
// with tracking of that code to enable hooking into it at run-time.

#pragma once

#include "zeek/Func.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek {

namespace detail {

// A subclass of Func used for lambdas that the compiler creates for
// complex initializations (expressions used in type attributes).
// The usage is via derivation from this class, rather than direct
// use of it.

class CPPFunc : public Func {
public:
	bool IsPure() const override	{ return is_pure; }

	void Describe(ODesc* d) const override;

protected:
	// Constructor used when deriving subclasses.
	CPPFunc(const char* _name, bool _is_pure)
		{
		name = _name;
		is_pure = _is_pure;
		}

	std::string name;
	bool is_pure;
};


// A subclass of Stmt used to replace a function/event handler/hook body.

class CPPStmt : public Stmt {
public:
	CPPStmt(const char* _name) : Stmt(STMT_CPP), name(_name)	{ }

	const std::string& Name()	{ return name; }

	// The following only get defined by lambda bodies.
	virtual void SetLambdaCaptures(Frame* f)	{ }
	virtual std::vector<ValPtr> SerializeLambdaCaptures() const
		{ return std::vector<ValPtr>{}; }

	virtual IntrusivePtr<CPPStmt> Clone()	
		{
		return {NewRef{}, this};
		}

protected:
	// This method being called means that the inliner is running
	// on compiled code, which shouldn't happen.
	StmtPtr Duplicate() override	{ ASSERT(0); return ThisPtr(); }

	TraversalCode Traverse(TraversalCallback* cb) const override
		{ return TC_CONTINUE; }

	std::string name;
};

using CPPStmtPtr = IntrusivePtr<CPPStmt>;


// For script-level lambdas, a ScriptFunc subclass that knows how to
// deal with its captures for serialization.  Different from CPPFunc in
// that CPPFunc is for lambdas generated directly by the compiler,
// rather than those explicitly present in scripts.

class CPPLambdaFunc : public ScriptFunc {
public:
	CPPLambdaFunc(std::string name, FuncTypePtr ft, CPPStmtPtr l_body);

	bool CopySemantics() const override	{ return true; }

protected:
	// Methods related to sending lambdas via Broker.
	broker::expected<broker::data> SerializeClosure() const override;
	void SetCaptures(Frame* f) override;

	FuncPtr DoClone() override;

	CPPStmtPtr l_body;
};


// Information associated with a given compiled script body: its
// Stmt subclass, priority, and any events that should be registered
// upon instantiating the body.
struct CompiledScript {
	CPPStmtPtr body; 
	int priority;
	std::vector<std::string> events;
};

// Maps hashes to compiled information.
extern std::unordered_map<hash_type, CompiledScript> compiled_scripts;

} // namespace detail

} // namespace zeek
