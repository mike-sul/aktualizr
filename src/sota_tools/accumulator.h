// accumulator.hpp header file
//
//  (C) Copyright benjaminwolsey.de 2010-2011. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef PROGRAM_OPTIONS_ACCUMULATOR_HPP
#define PROGRAM_OPTIONS_ACCUMULATOR_HPP

#include <functional>
#include <string>
#include <vector>

#include <boost/any.hpp>
#include <boost/program_options/value_semantic.hpp>

/// An accumulating option value to handle multiple incrementing options.
template <typename T>
class accumulator_type : public boost::program_options::value_semantic {
 public:
  explicit accumulator_type(T* store) : _store(store), _interval(1), _default(0) {}

  /// Set the notifier function.
  accumulator_type* notifier(std::function<void(const T&)> f) {
    _notifier = f;
    return this;
  }

  /// Set the default value for this option.
  accumulator_type* default_value(const T& t) {
    _default = t;
    return this;
  }

  /// Set the implicit value for this option.
  //
  /// Unlike for program_options::value, this specifies a value
  /// to be applied on each occurrence of the option.
  accumulator_type* implicit_value(const T& t) {
    _interval = t;
    return this;
  }

  virtual std::string name() const { return std::string(); }  // NOLINT

  /// There are no tokens for an accumulator_type
  virtual unsigned min_tokens() const { return 0; }  // NOLINT
  virtual unsigned max_tokens() const { return 0; }  // NOLINT

  virtual bool adjacent_tokens_only() const { return false; }  // NOLINT

  /// Accumulating from different sources is silly.
  virtual bool is_composing() const { return false; }  // NOLINT

  /// Requiring one or more appearances is unlikely.
  virtual bool is_required() const { return false; }  // NOLINT

  /// Every appearance of the option simply increments the value
  //
  /// There should never be any tokens.
  virtual void parse(boost::any& value_store, const std::vector<std::string>&, bool /*utf8*/) const {  // NOLINT
    if (value_store.empty()) {
      value_store = T();
    }
    boost::any_cast<T&>(value_store) += _interval;
  }

  /// If the option doesn't appear, this is the default value.
  virtual bool apply_default(boost::any& value_store) const {  // NOLINT
    value_store = _default;
    return true;
  }

  /// Notify the user function with the value of the value store.
  virtual void notify(const boost::any& value_store) const {  // NOLINT
    const auto* val = boost::any_cast<T>(&value_store);
    if (_store) {
      *_store = *val;
    }
    if (_notifier) {
      _notifier(*val);
    }
  }

  virtual ~accumulator_type() {}  // NOLINT

 private:
  T* _store;
  std::function<void(const T&)> _notifier;
  T _interval;
  T _default;
};

template <typename T>
accumulator_type<T>* accumulator() {
  return new accumulator_type<T>(0);
}

template <typename T>
accumulator_type<T>* accumulator(T* store) {
  return new accumulator_type<T>(store);
}

#endif
